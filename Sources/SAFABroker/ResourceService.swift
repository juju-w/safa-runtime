import Foundation
import SAFACrypto
import SAFADomain

actor ResourceMutationGate {
    private var locked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func withLock<Value: Sendable>(
        _ operation: @escaping @Sendable () async throws -> Value
    ) async throws -> Value {
        await acquire()
        do {
            let value = try await operation()
            release()
            return value
        } catch {
            release()
            throw error
        }
    }

    private func acquire() async {
        guard locked else {
            locked = true
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    private func release() {
        guard !waiters.isEmpty else {
            locked = false
            return
        }
        waiters.removeFirst().resume()
    }
}

public actor ResourceService {
    let vault: any VaultDocumentStoring
    let passwordStore: any PasswordSecretStoring
    let mutationGate = ResourceMutationGate()

    public init(
        vault: any VaultDocumentStoring,
        passwordStore: any PasswordSecretStoring
    ) {
        self.vault = vault
        self.passwordStore = passwordStore
    }

    public func resource(alias: ResourceAlias) async throws -> Resource {
        let document = try await vault.readDocument()
        guard
            let resource = document.resources.first(where: {
                ($0.alias == alias || $0.resolvedAlternateAliases.contains(alias))
                    && $0.state != .deleted
            })
        else {
            throw ResourceServiceError.notFound(alias: alias.rawValue)
        }
        return resource
    }
}
