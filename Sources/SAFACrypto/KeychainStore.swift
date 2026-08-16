import Foundation
import Security

public enum KeychainStoreError: Error, Equatable, Sendable {
    case unavailable
    case duplicate
    case invalidData
    case operationFailed
}

public enum KeychainItemPurpose: String, Codable, Sendable {
    case credential
    case vaultKey = "vault-key"
    case vaultRevision = "vault-revision"
}

public struct OpaqueKeychainLocator: Codable, Equatable, Hashable, Sendable {
    public let id: UUID
    public let purpose: KeychainItemPurpose

    public init(id: UUID, purpose: KeychainItemPurpose = .credential) {
        self.id = id
        self.purpose = purpose
    }

    public var account: String {
        "safa.\(purpose.rawValue).\(id.uuidString.lowercased())"
    }
}

public protocol VaultKeyStore: Sendable {
    func loadKey(id: UUID) async throws -> Data?
    func storeKey(_ key: Data, id: UUID) async throws
    func loadRevision(installationID: UUID) async throws -> UInt64?
    func storeRevision(_ revision: UInt64, installationID: UUID) async throws
}

public actor DataProtectionKeychainStore: VaultKeyStore {
    public static let service = "dev.safa.protected-store.v1"

    public init() {}

    public nonisolated static func baseQuery(for locator: OpaqueKeychainLocator) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: locator.account,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
    }

    public func loadKey(id: UUID) async throws -> Data? {
        try load(locator: OpaqueKeychainLocator(id: id, purpose: .vaultKey))
    }

    public func storeKey(_ key: Data, id: UUID) async throws {
        try store(key, locator: OpaqueKeychainLocator(id: id, purpose: .vaultKey))
    }

    public func loadRevision(installationID: UUID) async throws -> UInt64? {
        guard
            let data = try load(
                locator: OpaqueKeychainLocator(id: installationID, purpose: .vaultRevision)
            )
        else {
            return nil
        }
        guard let text = String(data: data, encoding: .utf8), let value = UInt64(text) else {
            throw KeychainStoreError.invalidData
        }
        return value
    }

    public func storeRevision(_ revision: UInt64, installationID: UUID) async throws {
        try store(
            Data(String(revision).utf8),
            locator: OpaqueKeychainLocator(id: installationID, purpose: .vaultRevision)
        )
    }

    private func load(locator: OpaqueKeychainLocator) throws -> Data? {
        var query = Self.baseQuery(for: locator)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw map(status) }
        guard let data = result as? Data else { throw KeychainStoreError.invalidData }
        return data
    }

    private func store(_ data: Data, locator: OpaqueKeychainLocator) throws {
        let query = Self.baseQuery(for: locator)
        let update = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else { throw map(updateStatus) }

        var insertion = query
        insertion[kSecValueData as String] = data
        let addStatus = SecItemAdd(insertion as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw map(addStatus) }
    }

    private func map(_ status: OSStatus) -> KeychainStoreError {
        switch status {
        case errSecDuplicateItem: .duplicate
        case errSecInteractionNotAllowed, errSecAuthFailed: .unavailable
        default: .operationFailed
        }
    }
}
