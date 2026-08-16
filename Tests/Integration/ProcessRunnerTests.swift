import Foundation
import SAFATransport
import Testing

@Suite("Bounded process runner")
struct ProcessRunnerTests {
    @Test("output bounds and remote exit are preserved")
    func boundedOutputAndExit() async throws {
        let result = try await ProcessRunner().run(
            ProcessInvocation(
                executableURL: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "printf 1234567890; exit 7"],
                timeoutSeconds: 2,
                outputLimitBytes: 5
            )
        )
        #expect(result.termination == .exit)
        #expect(result.exitCode == 7)
        #expect(result.stdout == Data("12345".utf8))
        #expect(result.stdoutTruncated)
    }

    @Test("deadline stops a child")
    func timeout() async throws {
        let result = try await ProcessRunner().run(
            ProcessInvocation(
                executableURL: URL(fileURLWithPath: "/bin/sleep"),
                arguments: ["2"],
                timeoutSeconds: 0,
                outputLimitBytes: 64
            )
        )
        #expect(result.termination == .timeout)
    }

    @Test("task cancellation propagates to the child")
    func cancellation() async throws {
        let task = Task {
            try await ProcessRunner().run(
                ProcessInvocation(
                    executableURL: URL(fileURLWithPath: "/bin/sleep"),
                    arguments: ["5"],
                    timeoutSeconds: 10,
                    outputLimitBytes: 64
                )
            )
        }
        try await Task.sleep(for: .milliseconds(50))
        task.cancel()
        #expect(try await task.value.termination == .cancelled)
    }
}
