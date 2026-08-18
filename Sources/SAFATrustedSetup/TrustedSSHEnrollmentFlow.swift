import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol

enum TrustedSSHEnrollmentError: Error, Equatable, Sendable {
    case authorizationDenied
    case invalidHost
    case invalidPort
    case invalidUsername
    case unsupportedResourceType
    case hostIdentityUnavailable
    case hostFingerprintMismatch
    case invalidCredential
}

enum TrustedSSHEnrollmentInput {
    static func validHost(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= 255
            && value.first != "-"
            && value.unicodeScalars.allSatisfy {
                $0.isASCII
                    && (CharacterSet.alphanumerics.contains($0)
                        || ".:-_%".unicodeScalars.contains($0))
            }
    }

    static func validUsername(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= 255
            && !value.unicodeScalars.contains {
                CharacterSet.whitespacesAndNewlines.contains($0)
                    || $0.value < 0x20
                    || $0.value == 0x7F
            }
    }
}

struct TrustedSSHEnrollmentFlow: Sendable {
    private let console: any TrustedSetupConsole
    private let authorizer: any UserPresenceAuthorizing
    private let scanner: any SSHHostKeyScanning
    private let client: any TrustedLocalSetupClient

    init(
        console: any TrustedSetupConsole,
        authorizer: any UserPresenceAuthorizing,
        scanner: any SSHHostKeyScanning,
        client: any TrustedLocalSetupClient
    ) {
        self.console = console
        self.authorizer = authorizer
        self.scanner = scanner
        self.client = client
    }

    func enroll(
        alias: ResourceAlias,
        resourceType: ResourceTypeIdentifier,
        now: Date = Date()
    ) async throws {
        guard Self.supports(resourceType) else {
            throw TrustedSSHEnrollmentError.unsupportedResourceType
        }
        guard
            await authorizer.authorize(
                reason: "Configure protected SSH access for SAFA resource \(alias.rawValue)"
            )
        else {
            throw TrustedSSHEnrollmentError.authorizationDenied
        }

        let host = try await readProtectedLine("SSH host or IP (hidden): ")
        guard TrustedSSHEnrollmentInput.validHost(host) else {
            throw TrustedSSHEnrollmentError.invalidHost
        }
        let portText = try await readProtectedLine("SSH port [22] (hidden): ")
        guard let port = UInt16(portText.isEmpty ? "22" : portText), port > 0 else {
            throw TrustedSSHEnrollmentError.invalidPort
        }
        let username = try await readProtectedLine("Existing remote username (hidden): ")
        guard TrustedSSHEnrollmentInput.validUsername(username) else {
            throw TrustedSSHEnrollmentError.invalidUsername
        }

        let identity = try await scanner.scan(host: host, port: port, now: now)
        try await write(
            "Enter the host fingerprint from a trusted out-of-band source; "
                + "the value remains hidden.\n"
        )
        let expectedFingerprint = try await readProtectedLine(
            "Verified SHA256 host fingerprint (hidden): "
        )
        guard expectedFingerprint == identity.fingerprint else {
            throw TrustedSSHEnrollmentError.hostFingerprintMismatch
        }

        var password = try await readSecret("SSH password (hidden): ")
        defer { password.resetBytes(in: 0..<password.count) }
        guard !password.isEmpty else { throw TrustedSSHEnrollmentError.invalidCredential }
        let payload = ProtectedResourceSetupPayload(
            resourceType: resourceType.rawValue,
            host: host,
            port: port,
            username: username,
            securityDomain: "resource.\(alias.rawValue)",
            hostKeyAlgorithm: identity.algorithm,
            hostPublicKey: identity.publicKey,
            hostFingerprint: identity.fingerprint,
            credential: password,
            credentialKind: CredentialKind.sshPassword.rawValue,
            credentialRole: ResourceCredentialRole.primary.rawValue
        )
        let sessionID = try await client.begin(alias: alias)
        try await client.commit(sessionID: sessionID, payload: payload)
        try await write("SAFA resource \(alias.rawValue) was verified and activated.\n")
    }

    private func readProtectedLine(_ prompt: String) async throws -> String {
        var value = try await readSecret(prompt)
        defer { value.resetBytes(in: 0..<value.count) }
        guard let decoded = String(data: value, encoding: .utf8) else {
            throw TrustedSSHEnrollmentError.invalidHost
        }
        return decoded
    }

    private func readSecret(_ prompt: String) async throws -> Data {
        try await Task.detached(priority: .userInitiated) { [console] in
            try console.readSecret(prompt: prompt)
        }.value
    }

    private func write(_ text: String) async throws {
        try await Task.detached(priority: .userInitiated) { [console] in
            try console.write(text)
        }.value
    }

    private static func supports(_ resourceType: ResourceTypeIdentifier) -> Bool {
        resourceType == .hostLinux || resourceType == .hostMacOS || resourceType == .hostWindows
    }
}
