import Foundation
import SAFACrypto

public final class VaultHarness: @unchecked Sendable {
    public let directoryURL: URL
    public let vaultURL: URL
    public let keyStore: InMemoryVaultKeyStore

    public init() throws {
        directoryURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("safa-tests-\(UUID().uuidString)", isDirectory: true)
        vaultURL = directoryURL.appendingPathComponent("vault.json")
        keyStore = InMemoryVaultKeyStore()
        try FileManager.default.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true
        )
    }

    deinit {
        try? FileManager.default.removeItem(at: directoryURL)
    }

    public func readEnvelope() throws -> VaultEnvelope {
        try JSONDecoder().decode(VaultEnvelope.self, from: Data(contentsOf: vaultURL))
    }

    public func writeEnvelope(_ envelope: VaultEnvelope) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(envelope).write(to: vaultURL, options: .atomic)
    }
}
