import ArgumentParser
import SAFAProtocol

struct SetupCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(
        commandName: "setup",
        subcommands: [
            SetupStatusCommand.self, SetupActivateCommand.self, SetupDeactivateCommand.self,
        ]
    )

    mutating func run() async throws {
        let response = BrokerLifecyclePresentation.status(
            await SystemBrokerServiceLifecycle().status()
        )
        try finish(response)
    }
}

struct SetupStatusCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(commandName: "status")

    func run() async throws {
        try finish(
            BrokerLifecyclePresentation.status(
                await SystemBrokerServiceLifecycle().status()
            )
        )
    }
}

struct SetupActivateCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(commandName: "activate")

    func run() async throws {
        let result = await BrokerActivationUseCase(
            service: SystemBrokerServiceLifecycle()
        ).activate()
        try finish(BrokerLifecyclePresentation.activation(result))
    }
}

struct SetupDeactivateCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(
        commandName: "deactivate",
        abstract: "Disable the per-user SAFA broker after an explicit local request."
    )

    func run() async throws {
        let result = await BrokerDeactivationUseCase(
            service: SystemBrokerServiceLifecycle()
        ).deactivate()
        try finish(BrokerLifecyclePresentation.deactivation(result))
    }
}

private enum BrokerLifecyclePresentation {
    static func status(_ status: BrokerServiceStatus) -> AgentCLIResponseV2<AgentBrokerLifecycleV2>
    {
        switch status {
        case .enabled:
            response(command: "setup.status", status: .completed, brokerStatus: status)
        case .notRegistered, .notFound:
            response(
                command: "setup.status",
                status: .userActionRequired,
                brokerStatus: status,
                error: AgentCLIErrorV2(
                    code: "runtime.activation_required",
                    message: "The signed SAFA broker is not activated.",
                    retryable: true
                ),
                next: [
                    AgentNextCommandV2(
                        command: "safa setup activate",
                        reason: "Activate the verified per-user broker",
                        safeForAgent: true
                    )
                ]
            )
        case .requiresApproval:
            approvalResponse(command: "setup.status", status: status)
        }
    }

    static func activation(
        _ result: BrokerActivationResult
    ) -> AgentCLIResponseV2<AgentBrokerLifecycleV2> {
        switch result {
        case .activated:
            response(command: "setup.activate", status: .completed, brokerStatus: .enabled)
        case .alreadyEnabled:
            response(command: "setup.activate", status: .noOp, brokerStatus: .enabled)
        case .approvalRequired:
            approvalResponse(command: "setup.activate", status: .requiresApproval)
        case .runtimeNotBundled:
            response(
                command: "setup.activate",
                status: .failed,
                brokerStatus: .notFound,
                error: AgentCLIErrorV2(
                    code: "runtime.not_bundled",
                    message: "Run safa from its verified macOS runtime bundle.",
                    retryable: false
                )
            )
        case .registrationFailed:
            response(
                command: "setup.activate",
                status: .failed,
                brokerStatus: .notRegistered,
                error: AgentCLIErrorV2(
                    code: "runtime.activation_failed",
                    message: "The signed local broker could not be activated.",
                    retryable: true
                )
            )
        }
    }

    static func deactivation(
        _ result: BrokerDeactivationResult
    ) -> AgentCLIResponseV2<AgentBrokerLifecycleV2> {
        switch result {
        case .deactivated:
            response(command: "setup.deactivate", status: .completed, brokerStatus: .notRegistered)
        case .alreadyInactive:
            response(command: "setup.deactivate", status: .noOp, brokerStatus: .notRegistered)
        case .unregistrationFailed:
            response(
                command: "setup.deactivate",
                status: .failed,
                brokerStatus: .enabled,
                error: AgentCLIErrorV2(
                    code: "runtime.deactivation_failed",
                    message: "The signed local broker could not be deactivated.",
                    retryable: true
                )
            )
        }
    }

    private static func approvalResponse(
        command: String,
        status: BrokerServiceStatus
    ) -> AgentCLIResponseV2<AgentBrokerLifecycleV2> {
        response(
            command: command,
            status: .userActionRequired,
            brokerStatus: status,
            error: AgentCLIErrorV2(
                code: "local_action.background_item_required",
                message: "Enable the SAFA background item in System Settings.",
                retryable: false
            ),
            next: [
                AgentNextCommandV2(
                    command: "open System Settings > Login Items",
                    reason: "A local user must enable the signed background item",
                    safeForAgent: false
                )
            ]
        )
    }

    private static func response(
        command: String,
        status: AgentCLIStatusV2,
        brokerStatus: BrokerServiceStatus,
        error: AgentCLIErrorV2? = nil,
        next: [AgentNextCommandV2] = []
    ) -> AgentCLIResponseV2<AgentBrokerLifecycleV2> {
        AgentCLIResponseV2(
            command: command,
            status: status,
            payload: AgentBrokerLifecycleV2(brokerServiceStatus: brokerStatus.rawValue),
            error: error,
            next: next
        )
    }
}
