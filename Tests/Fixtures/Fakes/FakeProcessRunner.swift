import SAFATransport

public actor FakeProcessRunner: ProcessRunning {
    private let result: ProcessExecutionResult
    private var invocations: [ProcessInvocation] = []

    public init(result: ProcessExecutionResult) {
        self.result = result
    }

    public func run(_ invocation: ProcessInvocation) -> ProcessExecutionResult {
        invocation.didLaunch?(4242)
        invocations.append(invocation)
        return result
    }

    public func lastInvocation() -> ProcessInvocation? {
        invocations.last
    }
}

public typealias FakeTransport = FakeProcessRunner
