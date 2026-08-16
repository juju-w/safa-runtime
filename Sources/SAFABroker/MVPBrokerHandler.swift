import Foundation
import SAFACrypto
import SAFADomain
import SAFAPolicy
import SAFAProtocol
import SAFASSH
import SAFATransport

public actor MVPBrokerHandler: AgentOperationHandling, TrustedAppOperationHandling {
    private let vault: any VaultDocumentStoring
    private let passwordStore: any PasswordSecretStoring
    private let resourceService: ResourceService
    private let bindingStore: ChildCredentialBindingStore
    private let transport: SSHTransport
    private let diagnosticPolicy: DiagnosticCommandPolicy
    private let audit: AuditService
    private let askPassExecutable: URL
    private let workingDirectory: URL
    private var setupSessions: [UUID: ResourceAlias] = [:]

    public init(
        vault: any VaultDocumentStoring,
        passwordStore: any PasswordSecretStoring,
        bindingStore: ChildCredentialBindingStore,
        transport: SSHTransport = SSHTransport(),
        diagnosticPolicy: DiagnosticCommandPolicy = DiagnosticCommandPolicy(),
        audit: AuditService = AuditService(),
        askPassExecutable: URL,
        workingDirectory: URL
    ) {
        self.vault = vault
        self.passwordStore = passwordStore
        resourceService = ResourceService(vault: vault, passwordStore: passwordStore)
        self.bindingStore = bindingStore
        self.transport = transport
        self.diagnosticPolicy = diagnosticPolicy
        self.audit = audit
        self.askPassExecutable = askPassExecutable
        self.workingDirectory = workingDirectory
    }

    public func handle(
        _ operation: AgentClientOperation,
        caller: CallerIdentity,
        messageID: UUID
    ) async -> BrokerReply {
        do {
            switch operation {
            case .runtimeStatus:
                _ = try await vault.readDocument()
                return BrokerReply(
                    messageID: messageID,
                    status: .completed,
                    data: ["broker": .string("ready"), "vault": .string("ready")]
                )
            case let .listResources(state):
                let registry = try ResourceRegistry(
                    resources: try await vault.readDocument().resources)
                return BrokerReply(
                    messageID: messageID,
                    status: .completed,
                    data: [
                        "resources": .array(registry.list(state: state).map(Self.jsonProjection))
                    ]
                )
            case let .submitExecution(
                resourceAlias,
                command,
                privilege,
                intent,
                expectedEffect,
                rollback
            ):
                return try await execute(
                    alias: resourceAlias,
                    command: command,
                    privilege: privilege,
                    intent: intent,
                    expectedEffect: expectedEffect,
                    rollback: rollback,
                    caller: caller,
                    messageID: messageID
                )
            case let .openTrustedSetup(resourceAlias):
                return BrokerReply(
                    messageID: messageID,
                    status: .userActionRequired,
                    data: [
                        "resource": resourceAlias.map { .string($0.rawValue) } ?? .null,
                        "trusted_app": .string("SAFA"),
                    ]
                )
            case .getRequest, .waitRequest, .cancelRequest, .listGrants, .revokeGrant,
                .listAudit, .verifyAudit:
                return unsupported(messageID: messageID)
            }
        } catch ResourceRegistryError.notFound(let alias) {
            return failure(
                messageID: messageID,
                code: "resource_not_found",
                message: "The requested resource is not registered.",
                details: ["resource": .string(alias)]
            )
        } catch {
            return failure(
                messageID: messageID,
                code: "runtime_failure",
                message: "The broker could not complete the request."
            )
        }
    }

    public func handle(
        _ operation: TrustedAppOperation,
        caller: CallerIdentity,
        messageID: UUID
    ) async -> BrokerReply {
        do {
            switch operation {
            case let .beginPrivateSetup(resourceAlias):
                let sessionID = UUID()
                setupSessions[sessionID] = resourceAlias
                return BrokerReply(
                    messageID: messageID,
                    status: .completed,
                    data: ["setup_session_id": .string(sessionID.uuidString)]
                )
            case let .commitPrivateSetup(sessionID, protectedPayload):
                guard let alias = setupSessions.removeValue(forKey: sessionID) else {
                    return failure(
                        messageID: messageID,
                        code: "setup_session_invalid",
                        message: "The private setup session is invalid or expired."
                    )
                }
                let payload = try CanonicalCodec.decode(
                    ProtectedResourceSetupPayload.self,
                    from: protectedPayload,
                    maxBytes: 64 * 1_024
                )
                guard
                    !payload.host.isEmpty,
                    payload.host.utf8.count <= 255,
                    !payload.username.isEmpty,
                    payload.username.utf8.count <= 255,
                    payload.securityDomain.utf8.count <= 128,
                    payload.hostFingerprint.utf8.count <= 512
                else {
                    return failure(
                        messageID: messageID,
                        code: "invalid_setup",
                        message: "The trusted setup values are invalid."
                    )
                }
                let draft = PrivateResourceDraft(
                    alias: alias,
                    displayName: payload.displayName,
                    endpoint: ResourceEndpoint(host: payload.host, port: payload.port),
                    username: payload.username,
                    securityDomain: payload.securityDomain,
                    hostIdentity: HostIdentity(
                        algorithm: payload.hostKeyAlgorithm,
                        publicKey: payload.hostPublicKey,
                        fingerprint: payload.hostFingerprint,
                        verifiedAt: Date(),
                        verificationMethod: .manual,
                        status: .trusted
                    )
                )
                let document = try await vault.readDocument()
                let resource: Resource
                if document.resources.contains(where: {
                    $0.alias == alias && $0.state != .deleted
                }) {
                    resource = try await resourceService.edit(
                        alias: alias,
                        draft: draft,
                        replacementPassword: payload.password
                    )
                } else {
                    resource = try await resourceService.addPasswordResource(
                        draft,
                        password: payload.password
                    )
                }
                return BrokerReply(
                    messageID: messageID,
                    status: .completed,
                    data: ["resource": .string(resource.alias.rawValue)]
                )
            case .getApprovalPresentation, .decideApproval, .listSensitiveResourceDetails,
                .rotateHostIdentity, .exportRecovery, .importRecovery:
                return unsupported(messageID: messageID)
            }
        } catch {
            return failure(
                messageID: messageID,
                code: "private_setup_failed",
                message: "The trusted setup transaction failed."
            )
        }
    }

    private func execute(
        alias: ResourceAlias,
        command: CommandSpec,
        privilege: Privilege,
        intent: String,
        expectedEffect: String?,
        rollback: String?,
        caller: CallerIdentity,
        messageID: UUID
    ) async throws -> BrokerReply {
        guard privilege == .user,
            diagnosticPolicy.allowsAutomaticExecution(command),
            !intent.isEmpty
        else {
            return failure(
                messageID: messageID,
                code: "approval_not_in_mvp",
                message: "The diagnostic MVP permits only bounded read-only commands."
            )
        }
        let document = try await vault.readDocument()
        let registry = try ResourceRegistry(resources: document.resources)
        let resource = try registry.resource(alias: alias)
        guard resource.state == .active,
            resource.hostIdentity?.status == .trusted,
            let credentialID = resource.authRef,
            let secret = try await passwordStore.readSecret(id: credentialID)
        else {
            return failure(
                messageID: messageID,
                code: "resource_not_ready",
                message: "The resource needs trusted setup or repair."
            )
        }

        let fingerprint = try CanonicalCodec.requestFingerprint(
            RequestFingerprintMaterial(
                caller: caller,
                resourceID: resource.id,
                resourceRevision: resource.revision,
                command: command,
                privilege: privilege
            )
        )
        let requestID = UUID()
        await audit.recordRequest(alias: alias, fingerprint: fingerprint)
        await audit.recordDecision(
            alias: alias,
            fingerprint: fingerprint,
            decision: "allowed_read_only"
        )
        let binding = bindingStore.issue(
            secret: secret,
            requestID: requestID,
            childProcessID: 0,
            expiresAt: Date().addingTimeInterval(60)
        )
        let result: ProcessExecutionResult
        do {
            result = try await transport.execute(
                resource: resource,
                command: command,
                credential: .password(
                    childBinding: binding,
                    askPassExecutable: askPassExecutable
                ),
                workingRoot:
                    workingDirectory
                    .appendingPathComponent(requestID.uuidString, isDirectory: true),
                didLaunch: { [bindingStore] childProcessID in
                    try? bindingStore.bind(
                        token: binding,
                        childProcessID: childProcessID
                    )
                }
            )
        } catch {
            bindingStore.revoke(requestID: requestID)
            await audit.recordExecution(
                alias: alias,
                fingerprint: fingerprint,
                outcome: "transport_failed"
            )
            return failure(
                messageID: messageID,
                code: "transport_failure",
                message: "The resource could not be reached securely."
            )
        }
        bindingStore.revoke(requestID: requestID)

        let stdout = Self.redact(secret, from: result.stdout)
        let stderr = Self.redact(secret, from: result.stderr)
        let outcome = result.exitCode == 0 ? "completed" : "remote_failure"
        await audit.recordExecution(alias: alias, fingerprint: fingerprint, outcome: outcome)
        return BrokerReply(
            messageID: messageID,
            status: .completed,
            data: [
                "request_id": .string(requestID.uuidString),
                "resource": .string(alias.rawValue),
                "intent": .string(String(intent.prefix(1_024))),
                "expected_effect": expectedEffect.map { .string(String($0.prefix(1_024))) }
                    ?? .null,
                "rollback": rollback.map { .string(String($0.prefix(1_024))) } ?? .null,
                "execution": .object([
                    "termination": .string(result.termination.rawValue),
                    "remote_exit_code": result.exitCode.map { .integer(Int64($0)) } ?? .null,
                    "stdout": .object([
                        "text": .string(String(decoding: stdout, as: UTF8.self)),
                        "captured_bytes": .integer(Int64(stdout.count)),
                        "truncated": .boolean(result.stdoutTruncated),
                    ]),
                    "stderr": .object([
                        "text": .string(String(decoding: stderr, as: UTF8.self)),
                        "captured_bytes": .integer(Int64(stderr.count)),
                        "truncated": .boolean(result.stderrTruncated),
                    ]),
                ]),
            ]
        )
    }

    private static func redact(_ secret: Data, from data: Data) -> Data {
        guard !secret.isEmpty else { return data }
        var result = data
        let replacement = Data("[REDACTED]".utf8)
        while let range = result.range(of: secret) {
            result.replaceSubrange(range, with: replacement)
        }
        return result
    }

    private static func jsonProjection(_ resource: SafeResourceProjection) -> JSONValue {
        .object([
            "alias": .string(resource.alias.rawValue),
            "transport": .string(resource.transport.rawValue),
            "state": .string(resource.state.rawValue),
            "capabilities": .array(resource.capabilities.map(JSONValue.string)),
            "health": .string(resource.health.rawValue),
        ])
    }

    private func unsupported(messageID: UUID) -> BrokerReply {
        failure(
            messageID: messageID,
            code: "not_available_in_mvp",
            message: "This operation is not available in the diagnostic MVP."
        )
    }

    private func failure(
        messageID: UUID,
        code: String,
        message: String,
        details: [String: JSONValue] = [:]
    ) -> BrokerReply {
        BrokerReply(
            messageID: messageID,
            status: .failed,
            error: SAFAErrorPayload(
                code: code,
                message: message,
                retryable: false,
                details: details
            )
        )
    }
}
