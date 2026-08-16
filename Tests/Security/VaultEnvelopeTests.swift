import Foundation
import SAFACrypto
import SAFADomain
import SAFATestFixtures
import Testing

@Suite("Authenticated encrypted vault envelope")
struct VaultEnvelopeTests {
    @Test("ciphertext tampering fails closed")
    func tamperFails() async throws {
        let harness = try VaultHarness()
        let vault = EncryptedVault(fileURL: harness.vaultURL, keyStore: harness.keyStore)
        _ = try await vault.initialize(document: .empty)

        var envelope = try harness.readEnvelope()
        envelope.ciphertext[0] ^= 0x01
        try harness.writeEnvelope(envelope)

        await #expect(throws: VaultError.authenticationFailed) {
            _ = try await vault.load()
        }
    }

    @Test("copying the vault without its installation key is unusable")
    func copiedVaultFails() async throws {
        let source = try VaultHarness()
        let sourceVault = EncryptedVault(fileURL: source.vaultURL, keyStore: source.keyStore)
        _ = try await sourceVault.initialize(document: .empty)

        let destination = try VaultHarness()
        try FileManager.default.copyItem(at: source.vaultURL, to: destination.vaultURL)
        let copiedVault = EncryptedVault(
            fileURL: destination.vaultURL,
            keyStore: destination.keyStore
        )

        await #expect(throws: VaultError.keyUnavailable) {
            _ = try await copiedVault.load()
        }
    }

    @Test("an authenticated older revision is rejected after an update")
    func rollbackFails() async throws {
        let harness = try VaultHarness()
        let vault = EncryptedVault(fileURL: harness.vaultURL, keyStore: harness.keyStore)
        _ = try await vault.initialize(document: .empty)
        let revisionOne = try Data(contentsOf: harness.vaultURL)
        _ = try await vault.update(document: VaultDocument(schemaVersion: 1, resources: []))
        try revisionOne.write(to: harness.vaultURL, options: .atomic)

        await #expect(throws: VaultError.rollbackDetected) {
            _ = try await vault.load()
        }
    }
}
