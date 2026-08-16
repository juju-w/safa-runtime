import Foundation

public enum PasswordCredentialError: Error, Equatable, Sendable {
    case invalidSecret
    case notFound
}

public protocol PasswordSecretStoring: Sendable {
    func storeSecret(_ secret: Data, id: UUID) async throws
    func readSecret(id: UUID) async throws -> Data?
    func deleteSecret(id: UUID) async throws
}

extension DataProtectionKeychainStore: PasswordSecretStoring {}

public struct PasswordCredential: Sendable {
    public static let maximumBytes = 16_384

    private let store: any PasswordSecretStoring

    public init(store: any PasswordSecretStoring) {
        self.store = store
    }

    @discardableResult
    public func create(secret: Data, id: UUID = UUID()) async throws -> OpaqueKeychainLocator {
        guard !secret.isEmpty,
            secret.count <= Self.maximumBytes,
            !secret.contains(0),
            !secret.contains(0x0A),
            !secret.contains(0x0D)
        else {
            throw PasswordCredentialError.invalidSecret
        }
        try await store.storeSecret(secret, id: id)
        return OpaqueKeychainLocator(id: id)
    }

    public func read(id: UUID) async throws -> Data {
        guard let secret = try await store.readSecret(id: id) else {
            throw PasswordCredentialError.notFound
        }
        return secret
    }

    public func delete(id: UUID) async throws {
        try await store.deleteSecret(id: id)
    }
}
