public struct AgentTextPreviewV2: Equatable, Sendable {
    public let text: String
    public let capturedBytes: Int
    public let originalBytes: Int
    public let truncated: Bool
    public let contentType: String

    public init(
        text: String,
        capturedBytes: Int,
        originalBytes: Int,
        truncated: Bool,
        contentType: String = "text"
    ) {
        self.text = text
        self.capturedBytes = capturedBytes
        self.originalBytes = originalBytes
        self.truncated = truncated
        self.contentType = contentType
    }
}

public struct AgentExecutionResultV2: Equatable, Sendable {
    public let resource: String
    public let intent: String
    public let termination: String
    public let remoteExitCode: Int32?
    public let stdout: AgentTextPreviewV2
    public let stderr: AgentTextPreviewV2

    public init(
        resource: String,
        intent: String,
        termination: String,
        remoteExitCode: Int32?,
        stdout: AgentTextPreviewV2,
        stderr: AgentTextPreviewV2
    ) {
        self.resource = resource
        self.intent = intent
        self.termination = termination
        self.remoteExitCode = remoteExitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}
