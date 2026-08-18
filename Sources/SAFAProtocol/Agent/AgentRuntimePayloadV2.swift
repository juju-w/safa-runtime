public struct AgentRuntimeStatusV2: Equatable, Sendable {
    public let broker: String
    public let vault: String

    public init(broker: String, vault: String) {
        self.broker = broker
        self.vault = vault
    }
}

public struct AgentBrokerLifecycleV2: Equatable, Sendable {
    public let brokerServiceStatus: String

    public init(brokerServiceStatus: String) {
        self.brokerServiceStatus = brokerServiceStatus
    }
}

public struct AgentUsageFailureV2: Equatable, Sendable {
    public let validFlags: [String]

    public init(validFlags: [String]) {
        self.validFlags = validFlags
    }
}
