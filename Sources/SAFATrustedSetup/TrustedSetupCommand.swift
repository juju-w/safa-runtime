import ArgumentParser
import Foundation
import SAFACrypto
import SAFADomain

public struct TrustedSetupCommand: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "safa-trusted-setup",
        abstract: "System-authenticated local configuration for protected SAFA resource values.",
        subcommands: [TrustedResourceCommand.self]
    )

    public init() {}
}

struct TrustedResourceCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "resource",
        subcommands: [TrustedResourceAddCommand.self]
    )
}

struct TrustedResourceAddCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "add",
        abstract: "Collect and verify protected SSH configuration from the controlling terminal."
    )

    @Argument(help: "Safe logical SAFA resource alias.") var alias: String
    @Option(
        name: .customLong("type"),
        help: "Host type: host.linux, host.macos, or host.windows."
    ) var resourceType = ResourceTypeIdentifier.hostLinux.rawValue

    mutating func run() async throws {
        let console = try TTYTrustedSetupConsole()
        do {
            try await TrustedSSHEnrollmentFlow(
                console: console,
                authorizer: LocalAuthenticationUserPresenceAuthorizer(),
                scanner: SystemSSHHostKeyScanner(),
                client: XPCTrustedLocalSetupClient()
            ).enroll(
                alias: try ResourceAlias(alias),
                resourceType: try ResourceTypeIdentifier(resourceType)
            )
        } catch {
            try? console.write("SAFA protected setup did not complete.\n")
            throw ExitCode.failure
        }
    }
}

public enum TrustedSetupRuntime {
    public static func main() async {
        await TrustedSetupCommand.main()
    }
}
