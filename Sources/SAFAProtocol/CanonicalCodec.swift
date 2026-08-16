import CryptoKit
import Foundation
import SAFADomain

public enum ProtocolCodecError: Error, Equatable, Sendable {
    case inputTooLarge(limit: Int)
    case invalidSchema
}

public struct RequestFingerprintMaterial: Codable, Equatable, Sendable {
    public let caller: CallerIdentity
    public let resourceID: UUID
    public let resourceRevision: UInt64
    public let command: CommandSpec
    public let privilege: Privilege

    public init(
        caller: CallerIdentity,
        resourceID: UUID,
        resourceRevision: UInt64,
        command: CommandSpec,
        privilege: Privilege
    ) {
        self.caller = caller
        self.resourceID = resourceID
        self.resourceRevision = resourceRevision
        self.command = command
        self.privilege = privilege
    }
}

public enum CanonicalCodec {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(value)
    }

    public static func decode<T: Decodable>(
        _ type: T.Type,
        from data: Data,
        maxBytes: Int = 1_048_576
    ) throws -> T {
        guard data.count <= maxBytes else {
            throw ProtocolCodecError.inputTooLarge(limit: maxBytes)
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(type, from: data)
    }

    public static func decode(
        _ type: CLIEnvelope.Type,
        from data: Data,
        maxBytes: Int = 1_048_576
    ) throws -> CLIEnvelope {
        let envelope: CLIEnvelope = try decodeRaw(type, from: data, maxBytes: maxBytes)
        guard envelope.schema == CLIEnvelope.currentSchema,
            envelope.command.utf8.count <= 128,
            envelope.warnings.count <= 64,
            envelope.warnings.allSatisfy({ $0.utf8.count <= 1_024 })
        else {
            throw ProtocolCodecError.invalidSchema
        }
        return envelope
    }

    public static func requestFingerprint(_ material: RequestFingerprintMaterial) throws -> String {
        let bytes = try encode(material)
        return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    private static func decodeRaw<T: Decodable>(
        _ type: T.Type,
        from data: Data,
        maxBytes: Int
    ) throws -> T {
        guard data.count <= maxBytes else {
            throw ProtocolCodecError.inputTooLarge(limit: maxBytes)
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(type, from: data)
    }
}
