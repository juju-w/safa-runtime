public struct AgentHomePayloadV2: Equatable, Sendable {
    public let binary: String
    public let description: String
    public let broker: String
    public let vault: String
    public let resources: AgentResourceListV2

    public init(
        binary: String,
        description: String,
        broker: String,
        vault: String,
        resources: AgentResourceListV2
    ) {
        self.binary = binary
        self.description = description
        self.broker = broker
        self.vault = vault
        self.resources = resources
    }
}

public struct AgentHelpPayloadV2: Equatable, Sendable {
    public let text: String

    public init(text: String) {
        self.text = text
    }
}
