import Testing

@testable import SAFACLI

@Suite("Broker activation lifecycle")
struct BrokerActivationContractTests {
    @Test("activation is idempotent and registers only an unregistered service")
    func activationTransitions() async {
        let enabled = FakeBrokerServiceLifecycle(status: .enabled)
        let enabledResult = await BrokerActivationUseCase(service: enabled).activate()
        #expect(enabledResult == .alreadyEnabled)
        #expect(await enabled.registrationCount() == 0)

        let unregistered = FakeBrokerServiceLifecycle(
            status: .notRegistered,
            statusAfterRegistration: .enabled
        )
        let activationResult = await BrokerActivationUseCase(service: unregistered).activate()
        #expect(activationResult == .activated)
        #expect(await unregistered.registrationCount() == 1)
    }

    @Test("system approval does not trigger another registration")
    func failClosedStates() async {
        let approval = FakeBrokerServiceLifecycle(status: .requiresApproval)
        #expect(
            await BrokerActivationUseCase(service: approval).activate() == .approvalRequired
        )
        #expect(await approval.registrationCount() == 0)
    }

    @Test("a missing background-task record is verified by registration")
    func missingRecordRegistration() async {
        let firstRegistration = FakeBrokerServiceLifecycle(
            status: .notFound,
            statusAfterRegistration: .enabled
        )
        #expect(
            await BrokerActivationUseCase(service: firstRegistration).activate() == .activated
        )
        #expect(await firstRegistration.registrationCount() == 1)

        let missing = FakeBrokerServiceLifecycle(
            status: .notFound,
            registrationError: SyntheticRegistrationError()
        )
        #expect(await BrokerActivationUseCase(service: missing).activate() == .runtimeNotBundled)
        #expect(await missing.registrationCount() == 1)
    }

    @Test("registration failures expose only a stable lifecycle result")
    func registrationFailure() async {
        let failing = FakeBrokerServiceLifecycle(
            status: .notRegistered,
            registrationError: SyntheticRegistrationError()
        )

        #expect(await BrokerActivationUseCase(service: failing).activate() == .registrationFailed)
        #expect(await failing.registrationCount() == 1)
    }

    @Test("deactivation unregisters only an enabled or approval-blocked service")
    func deactivationTransitions() async {
        let enabled = FakeBrokerServiceLifecycle(status: .enabled)
        #expect(await BrokerDeactivationUseCase(service: enabled).deactivate() == .deactivated)
        #expect(await enabled.unregistrationCount() == 1)

        let inactive = FakeBrokerServiceLifecycle(status: .notRegistered)
        #expect(
            await BrokerDeactivationUseCase(service: inactive).deactivate() == .alreadyInactive
        )
        #expect(await inactive.unregistrationCount() == 0)

        let failing = FakeBrokerServiceLifecycle(
            status: .enabled,
            unregistrationError: SyntheticRegistrationError()
        )
        #expect(
            await BrokerDeactivationUseCase(service: failing).deactivate()
                == .unregistrationFailed
        )
        #expect(await failing.unregistrationCount() == 1)
    }
}

private struct SyntheticRegistrationError: Error {}

private actor FakeBrokerServiceLifecycle: BrokerServiceLifecycle {
    private var currentStatus: BrokerServiceStatus
    private let statusAfterRegistration: BrokerServiceStatus
    private let registrationError: (any Error)?
    private let unregistrationError: (any Error)?
    private var registrations = 0
    private var unregistrations = 0

    init(
        status: BrokerServiceStatus,
        statusAfterRegistration: BrokerServiceStatus? = nil,
        registrationError: (any Error)? = nil,
        unregistrationError: (any Error)? = nil
    ) {
        currentStatus = status
        self.statusAfterRegistration = statusAfterRegistration ?? status
        self.registrationError = registrationError
        self.unregistrationError = unregistrationError
    }

    func status() async -> BrokerServiceStatus {
        currentStatus
    }

    func register() async throws {
        registrations += 1
        if let registrationError {
            throw registrationError
        }
        currentStatus = statusAfterRegistration
    }

    func unregister() async throws {
        unregistrations += 1
        if let unregistrationError {
            throw unregistrationError
        }
        currentStatus = .notRegistered
    }

    func registrationCount() -> Int {
        registrations
    }

    func unregistrationCount() -> Int {
        unregistrations
    }
}
