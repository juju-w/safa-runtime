import Foundation
import SAFACrypto

public actor InMemoryVaultKeyStore: VaultKeyStore {
    private var keys: [UUID: Data] = [:]
    private var revisions: [UUID: UInt64] = [:]

    public init() {}

    public func loadKey(id: UUID) async throws -> Data? {
        keys[id]
    }

    public func storeKey(_ key: Data, id: UUID) async throws {
        keys[id] = key
    }

    public func loadRevision(installationID: UUID) async throws -> UInt64? {
        revisions[installationID]
    }

    public func storeRevision(_ revision: UInt64, installationID: UUID) async throws {
        revisions[installationID] = revision
    }
}
