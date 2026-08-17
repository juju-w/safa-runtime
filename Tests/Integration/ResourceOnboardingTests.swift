import Foundation
import SAFABroker
import SAFACrypto
import SAFADomain
import SAFAProtocol
import SAFATestFixtures
import Testing

@Suite("Private resource onboarding")
struct ResourceOnboardingTests {
    @Test("trusted local setup accepts a typed service without exposing its secret")
    func trustedServiceSetup() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let resources = ResourceService(vault: vault, passwordStore: credentials)
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            resourceService: resources,
            askPassExecutable: URL(fileURLWithPath: "/synthetic/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
        )
        let alias = try ResourceAlias("mysql.test")
        let caller = CallerIdentity(
            signingIdentifier: "dev.safa.trusted-local",
            teamIdentifier: "TESTTEAM1",
            effectiveUserID: 501,
            auditSessionID: 77
        )
        let begin = await handler.handle(
            .beginPrivateSetup(resourceAlias: alias),
            caller: caller,
            messageID: UUID()
        )
        guard case let .string(sessionValue) = begin.data["setup_session_id"],
            let sessionID = UUID(uuidString: sessionValue)
        else {
            Issue.record("trusted setup did not return a session")
            return
        }
        let secret = Data("synthetic-database-password".utf8)
        let payload = ProtectedResourceSetupPayload(
            resourceType: ResourceTypeIdentifier.databaseMySQL.rawValue,
            host: "database.invalid",
            port: 3306,
            username: "reader",
            securityDomain: "synthetic",
            credential: secret,
            credentialKind: CredentialKind.databasePassword.rawValue,
            credentialRole: ResourceCredentialRole.readOnly.rawValue
        )
        let committed = await handler.handle(
            .commitPrivateSetup(
                sessionID: sessionID,
                protectedPayload: try CanonicalCodec.encode(payload)
            ),
            caller: caller,
            messageID: UUID()
        )

        #expect(committed.status == .completed)
        let resource = try await resources.resource(alias: alias)
        #expect(resource.resolvedResourceType == .databaseMySQL)
        #expect(resource.resolvedAccessMethods == [.mysql])
        #expect(resource.resolvedCredentialBindings.first?.role == .readOnly)
        #expect(SafeResourceProjection(resource: resource).health == .needsVerification)
        #expect(await credentials.readSecret(id: resource.authRef!) == secret)
        #expect(
            !String(decoding: try CanonicalCodec.encode(resource), as: UTF8.self).contains(
                "synthetic-database-password"))

        let editSession = await handler.handle(
            .beginPrivateSetup(resourceAlias: alias),
            caller: caller,
            messageID: UUID()
        )
        guard case let .string(editSessionValue) = editSession.data["setup_session_id"],
            let editSessionID = UUID(uuidString: editSessionValue)
        else {
            Issue.record("trusted edit did not return a session")
            return
        }
        let editedReply = await handler.handle(
            .commitPrivateSetup(
                sessionID: editSessionID,
                protectedPayload: try CanonicalCodec.encode(
                    ProtectedResourceSetupPayload(
                        displayName: "Synthetic database",
                        resourceType: ResourceTypeIdentifier.databaseMySQL.rawValue,
                        host: "database.invalid",
                        port: 3306,
                        username: "reader",
                        securityDomain: "synthetic"
                    )
                )
            ),
            caller: caller,
            messageID: UUID()
        )
        let edited = try await resources.resource(alias: alias)
        #expect(editedReply.status == .completed)
        #expect(edited.authRef == resource.authRef)
        #expect(edited.displayName == "Synthetic database")
        #expect(await credentials.readSecret(id: edited.authRef!) == secret)
    }

    @Test("SSH config import creates a real draft without inventing trust or credentials")
    func sshConfigDraftImport() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let resource = try await service.addDiscoveredResource(
            DiscoveredResourceDraft(
                alias: ResourceAlias("nas.home"),
                resourceType: .hostLinux,
                displayName: "Home NAS",
                endpoint: ResourceEndpoint(scheme: "ssh", host: "nas.internal", port: 2222),
                username: "operator",
                securityDomain: "local-ssh-config"
            ),
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        #expect(resource.state == .draft)
        #expect(resource.hostIdentity == nil)
        #expect(resource.authRef == nil)
        #expect(resource.endpoint?.host == "nas.internal")
        #expect(resource.username == "operator")
        #expect(await vault.readDocument().credentialReferences.isEmpty)
        #expect(SafeResourceProjection(resource: resource).health == .needsSetup)
    }

    @Test("SSH config refresh cannot silently retarget a trusted resource")
    func discoveredEditRejectsTrustedRetargeting() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let service = ResourceService(vault: vault, passwordStore: credentials)
        _ = try await service.addPasswordResource(
            PrivateResourceDraft.synthetic(alias: "nas.home"),
            password: Data("synthetic-password".utf8)
        )

        await #expect(throws: ResourceServiceError.unsafeConnectionChange) {
            try await service.editDiscoveredResource(
                alias: ResourceAlias("nas.home"),
                draft: DiscoveredResourceDraft(
                    alias: ResourceAlias("nas.home"),
                    resourceType: .hostLinux,
                    displayName: "Retargeted NAS",
                    endpoint: ResourceEndpoint(host: "other.internal", port: 22),
                    username: "operator",
                    securityDomain: "local-ssh-config"
                )
            )
        }
    }

    @Test("the trusted service commits metadata and a separate opaque password reference")
    func privatePasswordOnboarding() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let service = ResourceService(vault: vault, passwordStore: credentials)
        let secret = Data("synthetic-password".utf8)

        let resource = try await service.addPasswordResource(
            PrivateResourceDraft.synthetic(alias: "nas.home"),
            password: secret,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let document = await vault.readDocument()
        #expect(document.resources == [resource])
        #expect(document.credentialReferences.count == 1)
        #expect(document.credentialReferences[0].storageLocator != secret)
        #expect(await credentials.readSecret(id: resource.authRef!) == secret)
    }

    @Test("host profile metadata and aliases are committed into the encrypted document")
    func resourceProfileOnboarding() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let draft = try PrivateResourceDraft.synthetic(
            alias: "hm-105",
            alternateAliases: ["gpu-worker"],
            metadata: [
                ResourceMetadataEntry(key: "host.os.family", value: .text("linux")),
                ResourceMetadataEntry(key: "host.kernel.release", value: .text("6.8.0")),
                ResourceMetadataEntry(key: "host.cpu.logical-count", value: .integer(64)),
                ResourceMetadataEntry(
                    key: "host.memory.total-bytes",
                    value: .byteCount(274_877_906_944)
                ),
                ResourceMetadataEntry(key: "host.docker.available", value: .boolean(true)),
            ]
        )

        let resource = try await service.addPasswordResource(
            draft,
            password: Data("synthetic-password".utf8)
        )

        #expect(resource.resolvedResourceType == .hostLinux)
        #expect(resource.resolvedAlternateAliases.map(\.rawValue) == ["gpu-worker"])
        #expect(resource.resolvedMetadata == draft.metadata)
        #expect(
            try ResourceRegistry(resources: [resource])
                .resource(alias: ResourceAlias("gpu-worker")).id == resource.id
        )
    }

    @Test("onboarding rejects canonical or alternate alias collisions before storing a secret")
    func onboardingAliasCollision() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let service = ResourceService(vault: vault, passwordStore: credentials)
        _ = try await service.addPasswordResource(
            PrivateResourceDraft.synthetic(
                alias: "hm-105",
                alternateAliases: ["gpu-worker"]
            ),
            password: Data("first".utf8)
        )

        await #expect(throws: ResourceServiceError.duplicate(alias: "gpu-worker")) {
            try await service.addPasswordResource(
                PrivateResourceDraft.synthetic(alias: "gpu-worker"),
                password: Data("must-not-be-stored".utf8)
            )
        }
        #expect(await vault.readDocument().credentialReferences.count == 1)
    }

    @Test("onboarding rejects invalid public and credential-like metadata before storing a secret")
    func onboardingMetadataPolicy() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let service = ResourceService(vault: vault, passwordStore: credentials)
        let invalidDraft = try PrivateResourceDraft.synthetic(
            alias: "nas.home",
            metadata: [
                ResourceMetadataEntry(
                    key: "host.docker.available",
                    value: .text("https://private.example.invalid/token")
                )
            ]
        )

        await #expect(
            throws: ResourceServiceError.invalidMetadata("host.docker.available")
        ) {
            try await service.addPasswordResource(
                invalidDraft,
                password: Data("must-not-be-stored".utf8)
            )
        }
        #expect(await vault.readDocument().resources.isEmpty)
        #expect(await vault.readDocument().credentialReferences.isEmpty)

        let credentialDraft = try PrivateResourceDraft.synthetic(
            alias: "cache.internal",
            metadata: [
                ResourceMetadataEntry(
                    key: "service.api-token",
                    value: .text("synthetic-secret")
                )
            ]
        )
        await #expect(
            throws: ResourceServiceError.invalidMetadata("service.api-token")
        ) {
            try await service.addPasswordResource(
                credentialDraft,
                password: Data("must-also-not-be-stored".utf8)
            )
        }
        #expect(await vault.readDocument().resources.isEmpty)
        #expect(await vault.readDocument().credentialReferences.isEmpty)
    }

    @Test("onboarding rejects public key material and host fingerprints as metadata")
    func onboardingRejectsKeyMaterial() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )

        for (key, value) in [
            ("ssh.public-key", "ssh-ed25519 synthetic-public-material"),
            ("ssh.keypair", "synthetic-private-public-keypair"),
            ("ssh.keypairs", "synthetic-private-public-keypairs"),
            ("ssh.identity-file", "synthetic-private-key-locator"),
            ("ssh.pem", "synthetic-pem-material"),
            ("ssh.certificate", "synthetic-certificate-material"),
            ("host.fingerprint", "SHA256:synthetic-host-fingerprint"),
            ("service.keychain", "com.example.synthetic"),
            ("service.authorization", "Basic dXNlcjpwYXNz"),
            ("service.auth-header", "opaque-reference-42"),
            ("host.configuration", "Basic dXNlcjpwYXNz"),
            (
                "service.configuration",
                "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.deadbeef"
            ),
            (
                "service.configuration",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.deadbeef"
            ),
            (
                "service.configuration",
                "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..AAECAwQFBgcICQoL.c3ludGhldGlj.AAECAwQFBgcICQoLDA0ODw"
            ),
            ("database.connection-string", "postgresql://db-readonly.internal/app"),
            ("database.dsn", "postgresql://db-readonly.internal/app"),
            (
                "service.endpoint-description",
                "postgresql://operator:hunter2@db.internal/app"
            ),
            ("database.passphrase", "correct horse battery staple"),
            ("service.passcode", "873901"),
            ("database.pin", "420731"),
            ("service.jwk", #"{"kty":"oct","k":"c3ludGhldGlj"}"#),
            ("service.jwks", #"{"keys":[{"kty":"oct","k":"c3ludGhldGlj"}]}"#),
            ("service.runtime-config", #"{"kty":"oct","k":"c3ludGhldGlj"}"#),
            ("service.configuration", "Authorization: Bearer ABCDEFGHIJKLMNOP"),
            (
                "service.binary-config",
                "MC4CAQAwBQYDK2VwBCIEIFAzV2A2yFQSoeeXJT6eOFT0d+fHXGbR3G2Eetp4eWI5"
            ),
            (
                "service.encrypted-config",
                "MIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBV+3Y2CBVtXSO7ursZ8YLDAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQ/yY20LZR0Wy53ryidfpYGgRANRZZeU+qiyai0m/v38SdQmAlIWnyIDyjeigkSqNuILLh2OIwLDDFype8nVpuwD1cxCtp3zeKa2oyloA+cUH+Tw=="
            ),
            (
                "service.public-material",
                "MCowBQYDK2VwAyEAMXPgkm0Ch5sng3bHqTw6+kibp0nmIuej4RUH62qb+5w="
            ),
            (
                "service.rsa-public-material",
                "MEgCQQDO+8KOZfLsNVYtf8cyybQc9C77wN2oMdwZJ/3lNf55FlEnoiOdMDnGSfIuY8ka4ps4Dy2ODnHuReF+EwYi/xeDAgMBAAE="
            ),
            (
                "service.grouped-config",
                "MC4CAQAwBQ YDK2VwBCIE IFAzV2A2yF QSoeeXJT6e OFT0d+fHXG bR3G2Eetp4 eWI5"
            ),
            (
                "service.url-safe-config",
                "MC4CAQAwBQYDK2VwBCIEIFAzV2A2yFQSoeeXJT6eOFT0d-fHXGbR3G2Eetp4eWI5"
            ),
            (
                "service.ssh-wire-config",
                "AAAAC3NzaC1lZDI1NTE5AAAAIDFz4JJtAoebJ4N2x6k8OvpIm6dJ5iLno+EVB+tqm/uc"
            ),
            ("service.fragment-flood", String(repeating: "A ", count: 65)),
        ] {
            let draft = try PrivateResourceDraft.synthetic(
                alias: "nas.home",
                metadata: [
                    ResourceMetadataEntry(key: key, value: .text(value))
                ]
            )
            await #expect(throws: ResourceServiceError.invalidMetadata(key)) {
                try await service.addPasswordResource(
                    draft,
                    password: Data("must-not-be-stored".utf8)
                )
            }
        }

        #expect(await vault.readDocument().resources.isEmpty)
        #expect(await vault.readDocument().credentialReferences.isEmpty)
    }

    @Test("onboarding rejects a DER certificate split across a text list")
    func onboardingRejectsSplitDERCertificate() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let draft = try PrivateResourceDraft.synthetic(
            alias: "nas.home",
            metadata: [
                ResourceMetadataEntry(
                    key: "service.configuration",
                    value: .textList([
                        "MIIBTDCB/6ADAgECAhQNU6SL7ZiRRb2c2nHMfAbxK1/qVzAFBgMrZXAwHDEaMBgGA1UEAwwRc3ludGhldGljLmludmFsaWQwHhcNMjYwODE2MDg0NzE0WhcNMjYwODE3MDg0NzE0WjAcMRowGAYDVQQDDBFzeW50",
                        "aGV0aWMuaW52YWxpZDAqMAUGAytlcAMhANhvz6T7SomfyMONlzmOdGpUAA/oZGG1kaPgcuM9XxrMo1MwUTAdBgNVHQ4EFgQUpmdfUgngIDV/h5Y3y1TRQTKOI+EwHwYDVR0jBBgwFoAUpmdfUgngIDV/h5Y3y1TR",
                        "QTKOI+EwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQA0LZRmhlONVtG02Vz4wcA8sf0wGaTfbNziQK6mlaDbDdgy/KS/ytGjtEZ4UkLmPBUAkB90iDEG163lYS6ZUeED",
                    ])
                )
            ]
        )

        await #expect(throws: ResourceServiceError.invalidMetadata("service.configuration")) {
            try await service.addPasswordResource(
                draft,
                password: Data("must-not-be-stored".utf8)
            )
        }
        #expect(await vault.readDocument().resources.isEmpty)
        #expect(await vault.readDocument().credentialReferences.isEmpty)
    }

    @Test("onboarding rejects a PKCS12 container split across a text list")
    func onboardingRejectsSplitPKCS12Container() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        for chunks in [
            ["MBQCAQMwDwYJKoZI", "hvcNAQcBoAIEAA=="],
            ["MBQCAQMwDwYJKoZI", "hvcNAQcCoAIEAA=="],
        ] {
            let draft = try PrivateResourceDraft.synthetic(
                alias: "nas.home",
                metadata: [
                    ResourceMetadataEntry(
                        key: "service.configuration",
                        value: .textList(chunks)
                    )
                ]
            )

            await #expect(throws: ResourceServiceError.invalidMetadata("service.configuration")) {
                try await service.addPasswordResource(
                    draft,
                    password: Data("must-not-be-stored".utf8)
                )
            }
        }
        #expect(await vault.readDocument().resources.isEmpty)
        #expect(await vault.readDocument().credentialReferences.isEmpty)
    }

    @Test("onboarding rejects PuTTY private key material encoded as a text list")
    func onboardingRejectsPuTTYKeyMaterial() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let draft = try PrivateResourceDraft.synthetic(
            alias: "nas.home",
            metadata: [
                ResourceMetadataEntry(
                    key: "host.configuration",
                    value: .textList([
                        "PuTTY-User-Key-File-3: ssh-ed25519",
                        "Encryption: none",
                        "Comment: synthetic",
                        "Public-Lines: 1",
                        "c3ludGhldGljLXB1YmxpYy1tYXRlcmlhbA==",
                        "Private-Lines: 1",
                        "c3ludGhldGljLXByaXZhdGUtbWF0ZXJpYWw=",
                        "Private-MAC: synthetic-private-mac",
                    ])
                )
            ]
        )

        await #expect(throws: ResourceServiceError.invalidMetadata("host.configuration")) {
            try await service.addPasswordResource(
                draft,
                password: Data("must-not-be-stored".utf8)
            )
        }
        #expect(await vault.readDocument().resources.isEmpty)
        #expect(await vault.readDocument().credentialReferences.isEmpty)
    }

    @Test("onboarding rejects an authorization credential split across a text list")
    func onboardingRejectsSplitAuthorization() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let draft = try PrivateResourceDraft.synthetic(
            alias: "nas.home",
            metadata: [
                ResourceMetadataEntry(
                    key: "host.configuration",
                    value: .textList(["Basic", "dXNl", "cjpwYXNz"])
                )
            ]
        )

        await #expect(throws: ResourceServiceError.invalidMetadata("host.configuration")) {
            try await service.addPasswordResource(
                draft,
                password: Data("must-not-be-stored".utf8)
            )
        }
        #expect(await vault.readDocument().resources.isEmpty)
        #expect(await vault.readDocument().credentialReferences.isEmpty)
    }

    @Test("onboarding rejects SSH key material split across a text list")
    func onboardingRejectsSplitSSHKey() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let draft = try PrivateResourceDraft.synthetic(
            alias: "nas.home",
            metadata: [
                ResourceMetadataEntry(
                    key: "host.configuration",
                    value: .textList([
                        "ssh-ed25519",
                        "AAAAC3NzaC1lZDI1NTE5AAAAISyntheticPublicMaterial",
                    ])
                )
            ]
        )

        await #expect(throws: ResourceServiceError.invalidMetadata("host.configuration")) {
            try await service.addPasswordResource(
                draft,
                password: Data("must-not-be-stored".utf8)
            )
        }
        #expect(await vault.readDocument().resources.isEmpty)
        #expect(await vault.readDocument().credentialReferences.isEmpty)
    }

    @Test("onboarding rejects supported and legacy OpenSSH public key algorithms")
    func onboardingRejectsOpenSSHAlgorithms() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let algorithms = [
            "ssh-dss",
            "ssh-ed25519",
            "sk-ssh-ed25519@openssh.com",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "sk-ecdsa-sha2-nistp256@openssh.com",
            "ssh-rsa",
            "ssh-ed25519-cert-v01@openssh.com",
        ]

        for algorithm in algorithms {
            let draft = try PrivateResourceDraft.synthetic(
                alias: "nas.home",
                metadata: [
                    ResourceMetadataEntry(
                        key: "host.configuration",
                        value: .text("\(algorithm) AAAAB3NzaSyntheticPublicMaterial")
                    )
                ]
            )
            await #expect(throws: ResourceServiceError.invalidMetadata("host.configuration")) {
                try await service.addPasswordResource(
                    draft,
                    password: Data("must-not-be-stored".utf8)
                )
            }
        }

        #expect(await vault.readDocument().resources.isEmpty)
        #expect(await vault.readDocument().credentialReferences.isEmpty)
    }

    @Test("onboarding preserves safe typed extension metadata as protected detail")
    func onboardingPreservesPrivateExtensionMetadata() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let entry = try ResourceMetadataEntry(
            key: "database.replica-count",
            value: .integer(2)
        )
        let keyboardLayout = try ResourceMetadataEntry(
            key: "host.keyboard.layout",
            value: .text("us")
        )
        let health = try ResourceMetadataEntry(
            key: "service.health",
            value: .text("uncertain")
        )
        let documentationURL = try ResourceMetadataEntry(
            key: "service.documentation-url",
            value: .text("https://docs.example.invalid/health")
        )
        let transportStatus = try ResourceMetadataEntry(
            key: "service.transport-status",
            value: .text("ssh-service running")
        )
        let bearerProcessStatus = try ResourceMetadataEntry(
            key: "service.process-status",
            value: .text("bearer process active")
        )
        let artifactDigestInfo = try ResourceMetadataEntry(
            key: "service.artifact-digest",
            value: .text(
                "MDEwDQYJYIZIAWUDBAIBBQAEIBERERERERERERERERERERERERERERERERERERERERER"
            )
        )

        let resource = try await service.addPasswordResource(
            PrivateResourceDraft.synthetic(
                alias: "database.internal",
                metadata: [
                    entry, keyboardLayout, health, documentationURL, transportStatus,
                    bearerProcessStatus, artifactDigestInfo,
                ]
            ),
            password: Data("synthetic-password".utf8)
        )

        #expect(
            resource.resolvedMetadata
                == [
                    entry, keyboardLayout, health, documentationURL, transportStatus,
                    bearerProcessStatus, artifactDigestInfo,
                ]
        )
    }

    @Test("service templates share encrypted add, edit, show, and remove storage semantics")
    func serviceTemplateCRUD() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let service = ResourceService(vault: vault, passwordStore: credentials)
        let originalSecret = Data("synthetic-database-password".utf8)
        let replacementSecret = Data("replacement-database-password".utf8)
        let draft = PrivateResourceDraft(
            alias: try ResourceAlias("sqlserver.test"),
            resourceType: .databaseSQLServer,
            accessMethods: [.sqlServer],
            metadata: [
                try ResourceMetadataEntry(
                    key: "database.name",
                    value: .text("synthetic")
                )
            ],
            endpoint: ResourceEndpoint(
                scheme: "sqlserver",
                host: "database.invalid",
                port: 1433
            ),
            username: "reader",
            securityDomain: "synthetic",
            credentialKind: .databasePassword,
            credentialRole: .readOnly
        )

        let added = try await service.addProtectedResource(
            draft,
            credential: originalSecret
        )
        #expect(added.resolvedResourceType == .databaseSQLServer)
        #expect(added.transport == nil)
        #expect(added.hostIdentity == nil)
        #expect(added.resolvedCredentialBindings.first?.role == .readOnly)
        #expect(SafeResourceProjection(resource: added).capabilities.isEmpty)
        #expect(SafeResourceProjection(resource: added).health == .needsVerification)
        #expect(await credentials.readSecret(id: added.authRef!) == originalSecret)

        let verified = try await service.recordServiceVerification(
            alias: added.alias,
            expectedRevision: added.revision,
            adapter: .sqlServer,
            succeeded: true
        )
        #expect(SafeResourceProjection(resource: verified).health == .ready)

        let edited = try await service.edit(
            alias: verified.alias,
            draft: draft,
            replacementPassword: replacementSecret
        )
        #expect(edited.authRef != verified.authRef)
        #expect(edited.verification == nil)
        #expect(SafeResourceProjection(resource: edited).health == .needsVerification)
        #expect(await credentials.readSecret(id: added.authRef!) == nil)
        #expect(await credentials.readSecret(id: edited.authRef!) == replacementSecret)

        _ = try await service.remove(alias: edited.alias)
        #expect(await credentials.readSecret(id: edited.authRef!) == nil)
    }

    @Test("templates with optional authentication can be registered without a fake secret")
    func unauthenticatedServiceOnboarding() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let service = ResourceService(vault: vault, passwordStore: credentials)
        let resource = try await service.addProtectedResource(
            PrivateResourceDraft(
                alias: try ResourceAlias("health-api"),
                resourceType: .serviceHTTP,
                accessMethods: [.http],
                endpoint: ResourceEndpoint(
                    scheme: "https",
                    host: "service.invalid",
                    port: 443,
                    path: "/health"
                ),
                securityDomain: "synthetic",
                credentialKind: nil
            ),
            credential: nil
        )

        #expect(resource.authRef == nil)
        #expect(resource.resolvedCredentialBindings.isEmpty)
        #expect(SafeResourceProjection(resource: resource).health == .needsVerification)
        #expect(await vault.readDocument().credentialReferences.isEmpty)
    }

    @Test("template validation rejects mismatched adapters and credential kinds")
    func serviceTemplateValidation() async throws {
        let service = ResourceService(
            vault: InMemoryVaultDocumentStore(),
            passwordStore: InMemoryPasswordSecretStore()
        )
        let wrongAdapter = PrivateResourceDraft(
            alias: try ResourceAlias("sqlserver.test"),
            resourceType: .databaseSQLServer,
            accessMethods: [.redis],
            endpoint: ResourceEndpoint(host: "database.invalid", port: 1433),
            username: "reader",
            securityDomain: "synthetic",
            credentialKind: .databasePassword
        )
        await #expect(
            throws: ResourceServiceError.incompatibleAccessMethod("cache.redis")
        ) {
            try await service.addProtectedResource(
                wrongAdapter,
                credential: Data("synthetic".utf8)
            )
        }

        let wrongCredential = PrivateResourceDraft(
            alias: try ResourceAlias("redis.test"),
            resourceType: .cacheRedis,
            accessMethods: [.redis],
            endpoint: ResourceEndpoint(host: "cache.invalid", port: 6379),
            securityDomain: "synthetic",
            credentialKind: .apiToken
        )
        await #expect(
            throws: ResourceServiceError.incompatibleCredentialKind("service.api-token")
        ) {
            try await service.addProtectedResource(
                wrongCredential,
                credential: Data("synthetic".utf8)
            )
        }
    }

    @Test("editing an unknown alias does not expose an endpoint or credential")
    func unknownEdit() async {
        let service = ResourceService(
            vault: InMemoryVaultDocumentStore(),
            passwordStore: InMemoryPasswordSecretStore()
        )
        await #expect(throws: ResourceServiceError.notFound(alias: "missing.host")) {
            try await service.disable(alias: ResourceAlias("missing.host"))
        }
    }

    @Test("edit rotates the opaque credential and remove deletes the final secret")
    func editAndRemoveTransactions() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let service = ResourceService(vault: vault, passwordStore: credentials)
        let original = try await service.addPasswordResource(
            PrivateResourceDraft.synthetic(alias: "nas.home"),
            password: Data("old-password".utf8)
        )
        let edited = try await service.edit(
            alias: original.alias,
            draft: PrivateResourceDraft.synthetic(alias: "nas.home"),
            replacementPassword: Data("new-password".utf8)
        )

        #expect(edited.revision == original.revision + 1)
        #expect(edited.authRef != original.authRef)
        #expect(await credentials.readSecret(id: original.authRef!) == nil)
        #expect(await credentials.readSecret(id: edited.authRef!) == Data("new-password".utf8))

        let removed = try await service.remove(alias: edited.alias)
        #expect(removed.state == .deleted)
        #expect(await credentials.readSecret(id: edited.authRef!) == nil)
    }

    @Test("remove rejects a resource referenced by another live resource")
    func removeReferencedResource() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let host = try await service.addPasswordResource(
            PrivateResourceDraft.synthetic(alias: "nas.home"),
            password: Data("host-password".utf8)
        )
        _ = try await service.addPasswordResource(
            PrivateResourceDraft.synthetic(
                alias: "report.service",
                relationships: [
                    ResourceRelationship(kind: .hostedOn, targetResourceID: host.id)
                ]
            ),
            password: Data("service-password".utf8)
        )

        await #expect(
            throws: ResourceServiceError.referencedByResource(alias: "report.service")
        ) {
            try await service.remove(alias: host.alias)
        }

        let document = await vault.readDocument()
        #expect(document.resources.allSatisfy { $0.state == .active })
        #expect(try ResourceRegistry(resources: document.resources).list().count == 2)
        let relationshipEdge = try #require(
            document.topologyGraph?.edges.first(where: {
                $0.fromNodeID != host.id && $0.relation == .runsOn && $0.toNodeID == host.id
            }))
        #expect(relationshipEdge.layer == .desired)
        #expect(relationshipEdge.verification == .asserted)
    }
}

extension PrivateResourceDraft {
    static func synthetic(
        alias: String,
        alternateAliases: [String] = [],
        metadata: [ResourceMetadataEntry] = [],
        relationships: [ResourceRelationship] = []
    ) throws -> Self {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Self(
            alias: try ResourceAlias(alias),
            resourceType: .hostLinux,
            alternateAliases: try alternateAliases.map(ResourceAlias.init),
            accessMethods: [.ssh],
            metadata: metadata,
            relationships: relationships,
            displayName: "Synthetic NAS",
            endpoint: ResourceEndpoint(host: "203.0.113.10", port: 2222),
            username: "diagnostic-user",
            securityDomain: "synthetic",
            hostIdentity: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 7, count: 32),
                fingerprint: "SHA256:synthetic",
                verifiedAt: now,
                verificationMethod: .manual,
                status: .trusted
            )
        )
    }
}
