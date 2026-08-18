import Testing

@testable import SAFABroker

@Suite("Broker process environment")
struct BrokerProcessEnvironmentTests {
    @Test("runtime keeps only required non-secret environment values")
    func keepsOnlyRequiredValues() {
        let environment = BrokerProcessEnvironment.sanitized(
            inherited: [
                "API_TOKEN": "must-not-survive",
                "DYLD_INSERT_LIBRARIES": "/tmp/untrusted.dylib",
                "PATH": "/tmp/untrusted-bin",
                "SSH_AUTH_SOCK": "/private/tmp/agent.sock",
            ],
            homeDirectory: "/Users/example",
            username: "example",
            temporaryDirectory: "/private/tmp/"
        )

        #expect(
            environment == [
                "HOME": "/Users/example",
                "LOGNAME": "example",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "SSH_AUTH_SOCK": "/private/tmp/agent.sock",
                "TMPDIR": "/private/tmp/",
                "USER": "example",
            ]
        )
    }

    @Test("runtime rejects a relative SSH agent socket")
    func rejectsRelativeSocket() {
        let environment = BrokerProcessEnvironment.sanitized(
            inherited: ["SSH_AUTH_SOCK": "relative/agent.sock"],
            homeDirectory: "/Users/example",
            username: "example",
            temporaryDirectory: "/private/tmp/"
        )

        #expect(environment["SSH_AUTH_SOCK"] == nil)
    }

    @Test("broker re-exec replaces the inherited process image environment")
    func reexecEnvironmentIsMinimal() {
        let environment = BrokerProcessEnvironment.reexecEnvironment(
            inherited: [
                "API_TOKEN": "must-not-survive",
                "PATH": "/tmp/untrusted-bin",
                "SSH_AUTH_SOCK": "/private/tmp/agent.sock",
            ],
            homeDirectory: "/Users/example",
            username: "example",
            temporaryDirectory: "/private/tmp/",
            processIdentifier: 4242
        )

        #expect(environment["API_TOKEN"] == nil)
        #expect(environment["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin")
        #expect(environment["SSH_AUTH_SOCK"] == "/private/tmp/agent.sock")
        #expect(environment[BrokerProcessEnvironment.cleanReexecMarker] == "4242")
    }

    @Test("clean marker prevents a broker re-exec loop")
    func cleanMarkerPreventsLoop() {
        #expect(
            BrokerProcessEnvironment.requiresCleanReexec(
                inherited: [BrokerProcessEnvironment.cleanReexecMarker: "4242"],
                processIdentifier: 4242
            ) == false
        )
        #expect(
            BrokerProcessEnvironment.requiresCleanReexec(
                inherited: [BrokerProcessEnvironment.cleanReexecMarker: "1"],
                processIdentifier: 4242
            )
        )
        #expect(
            BrokerProcessEnvironment.requiresCleanReexec(
                inherited: [:],
                processIdentifier: 4242
            )
        )
    }
}
