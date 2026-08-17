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
}
