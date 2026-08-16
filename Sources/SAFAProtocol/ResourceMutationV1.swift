import Foundation
import SAFADomain

public enum ResourceMutationActionV1: String, Codable, Sendable {
    case add
    case edit
    case setup
    case disable
    case remove
}

/// Private connection values are resolved by the broker from a logical alias
/// and never cross the Agent XPC boundary.
public struct ResourceMutationV1: Codable, Equatable, Sendable {
    public let sourceSSHConfigAlias: ResourceAlias
    public let resourceType: ResourceTypeIdentifier?

    public init(
        sourceSSHConfigAlias: ResourceAlias,
        resourceType: ResourceTypeIdentifier? = nil
    ) {
        self.sourceSSHConfigAlias = sourceSSHConfigAlias
        self.resourceType = resourceType
    }

    private enum CodingKeys: String, CodingKey {
        case sourceSSHConfigAlias = "source_ssh_config_alias"
        case resourceType = "resource_type"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sourceSSHConfigAlias = try ResourceAlias(
            container.decode(String.self, forKey: .sourceSSHConfigAlias)
        )
        resourceType = try container.decodeIfPresent(String.self, forKey: .resourceType)
            .map(ResourceTypeIdentifier.init)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(sourceSSHConfigAlias.rawValue, forKey: .sourceSSHConfigAlias)
        try container.encodeIfPresent(resourceType?.rawValue, forKey: .resourceType)
    }
}

public struct ResourceMutationRequestV1: Codable, Equatable, Sendable {
    public let header: IPCHeader
    public let action: ResourceMutationActionV1
    public let alias: ResourceAlias
    public let mutation: ResourceMutationV1?

    public init(
        header: IPCHeader,
        action: ResourceMutationActionV1,
        alias: ResourceAlias,
        mutation: ResourceMutationV1? = nil
    ) {
        self.header = header
        self.action = action
        self.alias = alias
        self.mutation = mutation
    }

    private enum CodingKeys: String, CodingKey {
        case header
        case action
        case alias
        case mutation
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        header = try container.decode(IPCHeader.self, forKey: .header)
        action = try container.decode(ResourceMutationActionV1.self, forKey: .action)
        alias = try ResourceAlias(container.decode(String.self, forKey: .alias))
        mutation = try container.decodeIfPresent(ResourceMutationV1.self, forKey: .mutation)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(header, forKey: .header)
        try container.encode(action, forKey: .action)
        try container.encode(alias.rawValue, forKey: .alias)
        try container.encodeIfPresent(mutation, forKey: .mutation)
    }
}

public enum ResourceMutationReplyStatusV1: String, Codable, Sendable {
    case completed
    case userActionRequired = "user_action_required"
    case denied
    case failed
}

public struct ResourceMutationReplyV1: Codable, Equatable, Sendable {
    public let protocolVersion: UInt
    public let messageID: UUID
    public let status: ResourceMutationReplyStatusV1
    public let summary: ResourceSummaryV1?
    public let error: SAFAErrorPayload?

    public init(
        protocolVersion: UInt = IPCHeader.currentVersion,
        messageID: UUID,
        status: ResourceMutationReplyStatusV1,
        summary: ResourceSummaryV1? = nil,
        error: SAFAErrorPayload? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.messageID = messageID
        self.status = status
        self.summary = summary
        self.error = error
    }

    private enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case messageID = "message_id"
        case status
        case summary
        case error
    }
}
