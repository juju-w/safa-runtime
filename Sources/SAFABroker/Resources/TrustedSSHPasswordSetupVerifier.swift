import Foundation
import SAFADomain
import SAFASSH
import SAFATransport

public protocol TrustedSSHResourceVerifying: Sendable {
    func verify(
        draft: PrivateResourceDraft,
        password: Data,
        observedAt: Date
    ) async throws -> HostInventorySnapshot
}

public struct TrustedSSHPasswordSetupVerifier: TrustedSSHResourceVerifying {
    private let bindingStore: ChildCredentialBindingStore
    private let transport: SSHTransport
    private let inventoryProbe: any OpenSSHHostInventoryProbing
    private let askPassExecutable: URL
    private let workingDirectory: URL

    public init(
        bindingStore: ChildCredentialBindingStore,
        transport: SSHTransport = SSHTransport(),
        askPassExecutable: URL,
        workingDirectory: URL
    ) {
        self.init(
            bindingStore: bindingStore,
            transport: transport,
            inventoryProbe: nil,
            askPassExecutable: askPassExecutable,
            workingDirectory: workingDirectory
        )
    }

    init(
        bindingStore: ChildCredentialBindingStore,
        transport: SSHTransport = SSHTransport(),
        inventoryProbe: (any OpenSSHHostInventoryProbing)? = nil,
        askPassExecutable: URL,
        workingDirectory: URL
    ) {
        self.bindingStore = bindingStore
        self.transport = transport
        self.inventoryProbe =
            inventoryProbe
            ?? OpenSSHHostInventoryProbe(
                transport: transport,
                workingDirectory: workingDirectory
            )
        self.askPassExecutable = askPassExecutable
        self.workingDirectory = workingDirectory
    }

    public func verify(
        draft: PrivateResourceDraft,
        password: Data,
        observedAt: Date
    ) async throws -> HostInventorySnapshot {
        guard draft.accessMethods.contains(.ssh),
            draft.credentialKind == .sshPassword,
            let username = draft.username,
            !username.isEmpty,
            draft.hostIdentity?.status == .trusted,
            draft.classification.hostPlatform != nil
        else {
            throw TrustedResourceSetupError.invalidPayload
        }
        let candidate = Resource(
            id: UUID(),
            alias: draft.alias,
            classification: draft.classification,
            alternateAliases: draft.alternateAliases,
            accessMethods: draft.accessMethods,
            metadata: draft.metadata,
            relationships: draft.relationships,
            displayName: draft.displayName,
            transport: .ssh,
            endpoint: draft.endpoint,
            username: username,
            securityDomain: draft.securityDomain,
            hostIdentity: draft.hostIdentity,
            revision: 0,
            state: .active,
            createdAt: observedAt,
            updatedAt: observedAt
        )

        let accountResult = try await execute(
            resource: candidate,
            command: try CommandSpec.exec(
                arguments: candidate.resolvedHostPlatform == .windows ? ["whoami"] : ["id", "-un"],
                timeoutSeconds: 12,
                outputLimitBytes: 4_096
            ),
            password: password
        )
        if accountResult.termination == .exit, accountResult.exitCode == 255 {
            throw OpenSSHSetupVerifier.classifySSHFailure(accountResult.stderr)
        }
        let account = String(decoding: accountResult.stdout, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard accountResult.termination == .exit, accountResult.exitCode == 0,
            !accountResult.stdoutTruncated,
            Self.account(account, matches: username, platform: candidate.resolvedHostPlatform)
        else {
            throw ResourceSetupError.accountVerificationFailed
        }

        let binding = issue(password: password)
        defer { bindingStore.revoke(requestID: binding.requestID) }
        return try await inventoryProbe.probe(
            resource: candidate,
            credential: .password(
                childBinding: binding.token,
                askPassExecutable: askPassExecutable
            ),
            observedAt: observedAt,
            didLaunch: binding.didLaunch
        )
    }

    private func execute(
        resource: Resource,
        command: CommandSpec,
        password: Data
    ) async throws -> ProcessExecutionResult {
        let binding = issue(password: password)
        defer { bindingStore.revoke(requestID: binding.requestID) }
        return try await transport.execute(
            resource: resource,
            command: command,
            credential: .password(
                childBinding: binding.token,
                askPassExecutable: askPassExecutable
            ),
            workingRoot: workingDirectory.appendingPathComponent(
                "trusted-setup-\(binding.requestID.uuidString)",
                isDirectory: true
            ),
            didLaunch: binding.didLaunch
        )
    }

    private func issue(password: Data) -> PasswordExecutionBinding {
        let requestID = UUID()
        let token = bindingStore.issue(
            secret: password,
            requestID: requestID,
            childProcessID: 0,
            expiresAt: Date().addingTimeInterval(60)
        )
        return PasswordExecutionBinding(
            requestID: requestID,
            token: token,
            didLaunch: { [bindingStore] childProcessID in
                try? bindingStore.bind(token: token, childProcessID: childProcessID)
            }
        )
    }

    private static func account(
        _ observed: String,
        matches expected: String,
        platform: HostPlatform?
    ) -> Bool {
        guard platform == .windows else { return observed == expected }
        let account = observed.lowercased()
            .split(whereSeparator: { $0 == "\\" || $0 == "/" })
            .last
            .map(String.init)
        return account == expected.lowercased()
    }
}

private struct PasswordExecutionBinding: Sendable {
    let requestID: UUID
    let token: String
    let didLaunch: @Sendable (Int32) -> Void
}
