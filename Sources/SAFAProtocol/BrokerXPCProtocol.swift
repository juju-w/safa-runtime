import Foundation
import SAFADomain

public struct IPCHeader: Codable, Equatable, Sendable {
    public static let currentVersion: UInt = 1

    public let protocolVersion: UInt
    public let messageID: UUID
    public let sentAt: Date
    public let deadline: Date

    public init(
        protocolVersion: UInt = Self.currentVersion,
        messageID: UUID = UUID(),
        sentAt: Date,
        deadline: Date
    ) {
        self.protocolVersion = protocolVersion
        self.messageID = messageID
        self.sentAt = sentAt
        self.deadline = deadline
    }
}

public enum AgentClientOperation: Codable, Equatable, Sendable {
    case runtimeStatus
    case listResources(state: ResourceState?)
    case submitExecution(resourceAlias: ResourceAlias, command: CommandSpec, privilege: Privilege)
    case getRequest(id: UUID)
    case waitRequest(id: UUID, timeoutSeconds: UInt)
    case cancelRequest(id: UUID)
    case listGrants
    case revokeGrant(id: UUID)
    case listAudit(after: String?, limit: UInt)
    case verifyAudit
    case openTrustedSetup(resourceAlias: ResourceAlias?)
}

public enum TrustedAppOperation: Codable, Equatable, Sendable {
    case beginPrivateSetup(resourceAlias: ResourceAlias)
    case commitPrivateSetup(sessionID: UUID, protectedPayload: Data)
    case getApprovalPresentation(requestID: UUID)
    case decideApproval(requestID: UUID, approved: Bool, scope: ApprovalScope?)
    case listSensitiveResourceDetails(resourceID: UUID)
    case rotateHostIdentity(resourceID: UUID, protectedPayload: Data)
    case exportRecovery(protectedOptions: Data)
    case importRecovery(protectedPackage: Data)
}

public struct AgentClientMessage: Codable, Equatable, Sendable {
    public let header: IPCHeader
    public let operation: AgentClientOperation

    public init(header: IPCHeader, operation: AgentClientOperation) {
        self.header = header
        self.operation = operation
    }
}

public struct TrustedAppMessage: Codable, Equatable, Sendable {
    public let header: IPCHeader
    public let operation: TrustedAppOperation

    public init(header: IPCHeader, operation: TrustedAppOperation) {
        self.header = header
        self.operation = operation
    }
}
