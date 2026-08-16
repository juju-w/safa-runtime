import Foundation
import SAFACrypto
import SAFADomain

public actor InMemoryVaultDocumentStore: VaultDocumentStoring {
    private var document: VaultDocument

    public init(document: VaultDocument = .empty) {
        self.document = document
    }

    public func readDocument() -> VaultDocument {
        document
    }

    public func writeDocument(_ document: VaultDocument) {
        self.document = document
    }
}

public actor InMemoryPasswordSecretStore: PasswordSecretStoring {
    private var values: [UUID: Data] = [:]

    public init() {}

    public func storeSecret(_ secret: Data, id: UUID) {
        values[id] = secret
    }

    public func readSecret(id: UUID) -> Data? {
        values[id]
    }

    public func deleteSecret(id: UUID) {
        values.removeValue(forKey: id)
    }
}

public actor FakeApprovalProvider {
    private var decisions: [UUID: Bool]

    public init(decisions: [UUID: Bool] = [:]) {
        self.decisions = decisions
    }

    public func decision(for requestID: UUID) -> Bool? {
        decisions[requestID]
    }
}
