import Foundation

public struct ProtectedResourceSetupPayload: Codable, Equatable, Sendable {
    public let displayName: String?
    public let resourceType: String?
    public let alternateAliases: [String]?
    public let accessMethods: [String]?
    public let metadata: [ResourceMetadataEntryV1]?
    public let host: String
    public let port: UInt16
    public let scheme: String?
    public let path: String?
    public let username: String?
    public let securityDomain: String
    public let hostKeyAlgorithm: String?
    public let hostPublicKey: Data?
    public let hostFingerprint: String?
    /// Legacy SSH field retained for v1 decoding. New trusted clients use credential.
    public let password: Data?
    public let credential: Data?
    public let credentialKind: String?
    public let credentialRole: String?

    public init(
        displayName: String? = nil,
        resourceType: String? = nil,
        alternateAliases: [String]? = nil,
        accessMethods: [String]? = nil,
        metadata: [ResourceMetadataEntryV1]? = nil,
        host: String,
        port: UInt16 = 22,
        scheme: String? = nil,
        path: String? = nil,
        username: String? = nil,
        securityDomain: String,
        hostKeyAlgorithm: String? = nil,
        hostPublicKey: Data? = nil,
        hostFingerprint: String? = nil,
        password: Data? = nil,
        credential: Data? = nil,
        credentialKind: String? = nil,
        credentialRole: String? = nil
    ) {
        self.displayName = displayName
        self.resourceType = resourceType
        self.alternateAliases = alternateAliases
        self.accessMethods = accessMethods
        self.metadata = metadata
        self.host = host
        self.port = port
        self.scheme = scheme
        self.path = path
        self.username = username
        self.securityDomain = securityDomain
        self.hostKeyAlgorithm = hostKeyAlgorithm
        self.hostPublicKey = hostPublicKey
        self.hostFingerprint = hostFingerprint
        self.password = password
        self.credential = credential
        self.credentialKind = credentialKind
        self.credentialRole = credentialRole
    }
}
