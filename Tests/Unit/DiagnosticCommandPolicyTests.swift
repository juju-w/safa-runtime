import SAFADomain
import SAFAPolicy
import Testing

@Suite("Automatic diagnostic command policy")
struct DiagnosticCommandPolicyTests {
    private let policy = DiagnosticCommandPolicy()

    @Test(
        "bounded diagnostic forms are allowed",
        arguments: [
            ["true"],
            ["date"],
            ["hostname"],
            ["id"],
            ["uptime"],
            ["uname", "-a"],
            ["whoami"],
            ["df", "-h"],
            ["df", "-h", "/"],
            ["free", "-h"],
            ["systemctl", "is-active", "docker"],
            ["systemctl", "is-enabled", "docker.service"],
            ["docker", "version"],
            ["docker", "ps", "--format", DiagnosticCommandPolicy.dockerPSFormat],
            [
                "docker", "stats", "--no-stream", "--format",
                DiagnosticCommandPolicy.dockerStatsFormat,
            ],
            ["ps", "-eo", DiagnosticCommandPolicy.processFields, "--sort=-%cpu"],
            ["ps", "-eo", DiagnosticCommandPolicy.processFields, "--sort=-%mem"],
        ]
    )
    func allowsBoundedForms(_ arguments: [String]) throws {
        #expect(
            policy.allowsAutomaticExecution(
                try CommandSpec.exec(arguments: arguments)
            )
        )
    }

    @Test(
        "secret-dumping, state-changing, streaming, and ambiguous forms are denied",
        arguments: [
            ["ps", "e"],
            ["ps", "eww"],
            ["ps", "aux"],
            ["docker", "inspect", "api"],
            ["docker", "ps"],
            ["docker", "ps", "--format", "{{json .}}"],
            ["docker", "stats"],
            ["docker", "stats", "--no-stream"],
            ["systemctl", "show", "api"],
            ["systemctl", "status", "api"],
            ["systemctl", "restart", "api"],
            ["hostname", "-F", "/etc/hostname"],
            ["date", "-f", "/tmp/input"],
            ["df", "--output=source,target", "/"],
            ["uname", "--help"],
            ["sh", "-c", "true"],
        ]
    )
    func deniesUnsafeForms(_ arguments: [String]) throws {
        #expect(
            !policy.allowsAutomaticExecution(
                try CommandSpec.exec(arguments: arguments)
            )
        )
    }

    @Test("shell, stdin, tty, working directory, oversized limits, and sudo stay out of auto-run")
    func deniesAuthorityExpansion() throws {
        #expect(
            !policy.allowsAutomaticExecution(
                try CommandSpec.shell(program: "uptime")
            )
        )
        #expect(
            !policy.allowsAutomaticExecution(
                try CommandSpec.exec(arguments: ["uptime"], stdinMode: .boundedAgentData)
            )
        )
        #expect(
            !policy.allowsAutomaticExecution(
                try CommandSpec.exec(arguments: ["uptime"], tty: true)
            )
        )
        #expect(
            !policy.allowsAutomaticExecution(
                try CommandSpec.exec(arguments: ["uptime"], workingDirectory: "/tmp")
            )
        )
        #expect(
            !policy.allowsAutomaticExecution(
                try CommandSpec.exec(arguments: ["uptime"], timeoutSeconds: 61)
            )
        )
        #expect(
            !policy.allowsAutomaticExecution(
                try CommandSpec.exec(arguments: ["uptime"], outputLimitBytes: 1_048_577)
            )
        )
    }
}
