import Foundation
import SAFADomain
import Testing

@Suite("Domain validation and state transitions")
struct DomainStateTests {
    @Test("resource aliases accept only the public logical name grammar")
    func resourceAliasValidation() throws {
        #expect(try ResourceAlias("nas.home").rawValue == "nas.home")
        #expect(throws: DomainValidationError.self) { try ResourceAlias("") }
        #expect(throws: DomainValidationError.self) { try ResourceAlias("Prod Server") }
        #expect(throws: DomainValidationError.self) {
            try ResourceAlias(String(repeating: "a", count: 65))
        }
    }

    @Test("resource state transitions fail closed")
    func resourceStateTransitions() {
        #expect(ResourceState.draft.canTransition(to: .active))
        #expect(ResourceState.active.canTransition(to: .disabled))
        #expect(ResourceState.disabled.canTransition(to: .active))
        #expect(!ResourceState.deleted.canTransition(to: .active))
        #expect(!ResourceState.active.canTransition(to: .draft))
    }

    @Test("request transitions preserve terminal immutability")
    func requestStateTransitions() {
        #expect(RequestState.created.canTransition(to: .evaluating))
        #expect(RequestState.awaitingApproval.canTransition(to: .approvedByUser))
        #expect(RequestState.running.canTransition(to: .completed))
        #expect(!RequestState.completed.canTransition(to: .running))
        #expect(!RequestState.denied.canTransition(to: .evaluating))
    }

    @Test("command mode has exactly one payload")
    func commandSpecValidation() throws {
        let command = try CommandSpec.exec(arguments: ["systemctl", "is-active", "nginx"])
        #expect(command.mode == .exec)
        #expect(command.arguments?.count == 3)
        #expect(throws: DomainValidationError.self) { try CommandSpec.exec(arguments: []) }
        #expect(throws: DomainValidationError.self) { try CommandSpec.shell(program: "") }
    }
}
