import Foundation

public struct HostInventorySnapshot: Equatable, Sendable {
    public let platform: HostPlatform
    public let metadata: [ResourceMetadataEntry]

    public init(platform: HostPlatform, metadata: [ResourceMetadataEntry]) {
        self.platform = platform
        self.metadata = metadata
    }
}
