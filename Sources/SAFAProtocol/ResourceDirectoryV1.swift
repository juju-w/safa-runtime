import Foundation
import SAFADomain

public enum ResourceQueryActionV1: String, Codable, Sendable {
    case list
    case show
    case inspect
}

public struct ResourceDirectoryRequestV1: Codable, Equatable, Sendable {
    public let header: IPCHeader
    public let action: ResourceQueryActionV1
    public let alias: ResourceAlias?
    public let state: ResourceState?

    public init(
        header: IPCHeader,
        action: ResourceQueryActionV1,
        alias: ResourceAlias? = nil,
        state: ResourceState? = nil
    ) {
        self.header = header
        self.action = action
        self.alias = alias
        self.state = state
    }

    private enum CodingKeys: String, CodingKey {
        case header
        case action
        case alias
        case state
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        header = try container.decode(IPCHeader.self, forKey: .header)
        action = try container.decode(ResourceQueryActionV1.self, forKey: .action)
        if let rawAlias = try container.decodeIfPresent(String.self, forKey: .alias) {
            alias = try ResourceAlias(rawAlias)
        } else {
            alias = nil
        }
        state = try container.decodeIfPresent(ResourceState.self, forKey: .state)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(header, forKey: .header)
        try container.encode(action, forKey: .action)
        try container.encodeIfPresent(alias?.rawValue, forKey: .alias)
        try container.encodeIfPresent(state, forKey: .state)
    }
}

public enum ResourceDirectoryReplyStatusV1: String, Codable, Sendable {
    case completed
    case denied
    case failed
}

public struct ResourceDirectoryReplyV1: Codable, Equatable, Sendable {
    public let protocolVersion: UInt
    public let messageID: UUID
    public let status: ResourceDirectoryReplyStatusV1
    public let summaries: [ResourceSummaryV1]
    public let details: ResourceDetailsV1?
    public let error: SAFAErrorPayload?

    public init(
        protocolVersion: UInt = IPCHeader.currentVersion,
        messageID: UUID,
        status: ResourceDirectoryReplyStatusV1,
        summaries: [ResourceSummaryV1] = [],
        details: ResourceDetailsV1? = nil,
        error: SAFAErrorPayload? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.messageID = messageID
        self.status = status
        self.summaries = summaries
        self.details = details
        self.error = error
    }

    private enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case messageID = "message_id"
        case status
        case summaries
        case details
        case error
    }
}
