import Combine
import Foundation
import ServiceManagement

@MainActor
final class BrokerRegistration: ObservableObject {
    enum RegistrationError: Error {
        case requiresApproval
    }

    @Published private(set) var status: SMAppService.Status

    private let service: SMAppService

    init(plistName: String = "dev.safa.broker.plist") {
        service = SMAppService.agent(plistName: plistName)
        status = service.status
    }

    func refresh() {
        status = service.status
    }

    func register() throws {
        try service.register()
        refresh()
        if status == .requiresApproval {
            throw RegistrationError.requiresApproval
        }
    }
}
