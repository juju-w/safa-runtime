import Foundation
import SAFAAskPass
import SAFABroker
import Testing

@Suite("One-shot password askpass")
struct AskPassTests {
    @Test("a credential is bound to one child and consumed once")
    func oneShotBinding() async throws {
        let store = ChildCredentialBindingStore()
        let secret = Data("synthetic-password".utf8)
        let token = store.issue(
            secret: secret,
            requestID: UUID(),
            childProcessID: 4242,
            expiresAt: Date().addingTimeInterval(30)
        )
        let client = LocalAskPassClient(store: store)

        #expect(
            try await AskPassResponder(client: client).response(binding: token, parentPID: 4242)
                == secret)
        await #expect(throws: ChildCredentialBindingError.self) {
            try await AskPassResponder(client: client).response(binding: token, parentPID: 4242)
        }
        #expect(!token.contains("synthetic-password"))
    }

    @Test("a copied binding cannot be consumed by another process")
    func childMismatch() async {
        let store = ChildCredentialBindingStore()
        let token = store.issue(
            secret: Data("synthetic-password".utf8),
            requestID: UUID(),
            childProcessID: 4242,
            expiresAt: Date().addingTimeInterval(30)
        )
        #expect(throws: ChildCredentialBindingError.self) {
            try store.consume(token: token, childProcessID: 9999)
        }
    }

    @Test("an unbound credential becomes usable only for the launched child")
    func launchBinding() throws {
        let store = ChildCredentialBindingStore()
        let token = store.issue(
            secret: Data("synthetic-password".utf8),
            requestID: UUID(),
            childProcessID: 0,
            expiresAt: Date().addingTimeInterval(30)
        )

        try store.bind(token: token, childProcessID: 4242)
        #expect(
            try store.consume(token: token, childProcessID: 4242)
                == Data("synthetic-password".utf8)
        )
    }
}

private struct LocalAskPassClient: AskPassCredentialClient {
    let store: ChildCredentialBindingStore

    func consume(binding: String, parentPID: Int32) async throws -> Data {
        try store.consume(token: binding, childProcessID: parentPID)
    }
}
