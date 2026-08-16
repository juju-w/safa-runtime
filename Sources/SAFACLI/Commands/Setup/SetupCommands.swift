import ArgumentParser
import SAFAProtocol

struct SetupCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "setup",
        subcommands: [
            SetupStatusCommand.self, SetupActivateCommand.self, SetupDeactivateCommand.self,
        ]
    )
}

struct SetupStatusCommand: AsyncParsableCommand, JSONCommand {
    static let configuration = CommandConfiguration(commandName: "status")
    @Flag var json = false

    func run() async throws {
        let status = await SystemBrokerServiceLifecycle().status()
        let response = BrokerLifecyclePresentation.status(status)
        try emit(response.envelope, humanMessage: response.humanMessage)
        if let exitCode = response.exitCode {
            throw ExitCode(exitCode.rawValue)
        }
    }
}

struct SetupActivateCommand: AsyncParsableCommand, JSONCommand {
    static let configuration = CommandConfiguration(commandName: "activate")
    @Flag var json = false

    func run() async throws {
        let result = await BrokerActivationUseCase(
            service: SystemBrokerServiceLifecycle()
        ).activate()
        let response = BrokerLifecyclePresentation.activation(result)
        try emit(response.envelope, humanMessage: response.humanMessage)
        if let exitCode = response.exitCode {
            throw ExitCode(exitCode.rawValue)
        }
    }
}

struct SetupDeactivateCommand: AsyncParsableCommand, JSONCommand {
    static let configuration = CommandConfiguration(
        commandName: "deactivate",
        abstract:
            "Disable the per-user SAFA broker. This command is for the local user, not Agents."
    )
    @Flag var json = false

    func run() async throws {
        let result = await BrokerDeactivationUseCase(
            service: SystemBrokerServiceLifecycle()
        ).deactivate()
        let response = BrokerLifecyclePresentation.deactivation(result)
        try emit(response.envelope, humanMessage: response.humanMessage)
        if let exitCode = response.exitCode {
            throw ExitCode(exitCode.rawValue)
        }
    }
}

private struct BrokerLifecycleResponse {
    let envelope: CLIEnvelope
    let humanMessage: String
    let exitCode: SAFAProcessExit?
}

private enum BrokerLifecyclePresentation {
    static func status(_ status: BrokerServiceStatus) -> BrokerLifecycleResponse {
        switch status {
        case .enabled:
            response(command: "setup.status", status: status, message: "SAFA broker is enabled.")
        case .notRegistered:
            response(
                command: "setup.status",
                status: status,
                message: "SAFA broker is not activated.",
                cliStatus: .userActionRequired,
                nextAction: NextAction(
                    kind: "activate_runtime",
                    command: ["safa", "setup", "activate", "--json"],
                    safeForAgent: true
                ),
                exitCode: .userActionRequired
            )
        case .requiresApproval:
            approvalResponse(command: "setup.status", status: status)
        case .notFound:
            response(
                command: "setup.status",
                status: status,
                message: "SAFA broker has not been activated on this Mac.",
                cliStatus: .userActionRequired,
                nextAction: NextAction(
                    kind: "activate_runtime",
                    command: ["safa", "setup", "activate", "--json"],
                    safeForAgent: true
                ),
                exitCode: .userActionRequired
            )
        }
    }

    static func activation(_ result: BrokerActivationResult) -> BrokerLifecycleResponse {
        switch result {
        case .activated:
            return response(
                command: "setup.activate",
                status: .enabled,
                message: "SAFA broker was activated."
            )
        case .alreadyEnabled:
            return response(
                command: "setup.activate",
                status: .enabled,
                message: "SAFA broker is already enabled."
            )
        case .approvalRequired:
            return approvalResponse(command: "setup.activate", status: .requiresApproval)
        case .runtimeNotBundled:
            return runtimeNotBundledResponse(command: "setup.activate", status: .notFound)
        case .registrationFailed:
            let error = SAFAErrorPayload(
                code: "broker_activation_failed",
                message: "The signed local broker could not be activated.",
                retryable: true
            )
            return BrokerLifecycleResponse(
                envelope: CLIEnvelope(
                    command: "setup.activate",
                    status: .failed,
                    data: ["error": .object(error.jsonObject)]
                ),
                humanMessage: error.message,
                exitCode: .runtimeFailure
            )
        }
    }

    static func deactivation(_ result: BrokerDeactivationResult) -> BrokerLifecycleResponse {
        switch result {
        case .deactivated:
            return response(
                command: "setup.deactivate",
                status: .notRegistered,
                message: "SAFA broker was deactivated."
            )
        case .alreadyInactive:
            return response(
                command: "setup.deactivate",
                status: .notRegistered,
                message: "SAFA broker is already inactive."
            )
        case .unregistrationFailed:
            let error = SAFAErrorPayload(
                code: "broker_deactivation_failed",
                message: "The signed local broker could not be deactivated.",
                retryable: true
            )
            return BrokerLifecycleResponse(
                envelope: CLIEnvelope(
                    command: "setup.deactivate",
                    status: .failed,
                    data: ["error": .object(error.jsonObject)]
                ),
                humanMessage: error.message,
                exitCode: .runtimeFailure
            )
        }
    }

    private static func approvalResponse(
        command: String,
        status: BrokerServiceStatus
    ) -> BrokerLifecycleResponse {
        response(
            command: command,
            status: status,
            message: "Enable the SAFA background item in System Settings.",
            cliStatus: .userActionRequired,
            nextAction: NextAction(
                kind: "enable_background_item",
                command: [],
                safeForAgent: false
            ),
            exitCode: .userActionRequired
        )
    }

    private static func runtimeNotBundledResponse(
        command: String,
        status: BrokerServiceStatus
    ) -> BrokerLifecycleResponse {
        let error = SAFAErrorPayload(
            code: "runtime_not_bundled",
            message: "Run safa from its verified macOS runtime bundle.",
            retryable: false
        )
        return BrokerLifecycleResponse(
            envelope: CLIEnvelope(
                command: command,
                status: .failed,
                data: [
                    "broker_service_status": .string(status.rawValue),
                    "error": .object(error.jsonObject),
                ]
            ),
            humanMessage: error.message,
            exitCode: .runtimeFailure
        )
    }

    private static func response(
        command: String,
        status: BrokerServiceStatus,
        message: String,
        cliStatus: CLIStatus = .completed,
        nextAction: NextAction? = nil,
        exitCode: SAFAProcessExit? = nil
    ) -> BrokerLifecycleResponse {
        BrokerLifecycleResponse(
            envelope: CLIEnvelope(
                command: command,
                status: cliStatus,
                data: ["broker_service_status": .string(status.rawValue)],
                nextAction: nextAction
            ),
            humanMessage: message,
            exitCode: exitCode
        )
    }
}
