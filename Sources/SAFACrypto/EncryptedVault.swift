import CryptoKit
import Foundation
import SAFADomain

public enum VaultError: Error, Equatable, Sendable {
    case alreadyInitialized
    case notInitialized
    case keyUnavailable
    case authenticationFailed
    case rollbackDetected
    case unsupportedFormat
    case persistenceFailed
}

public protocol VaultDocumentStoring: Sendable {
    func readDocument() async throws -> VaultDocument
    func writeDocument(_ document: VaultDocument) async throws
}

public struct VaultEnvelope: Codable, Equatable, Sendable {
    public let formatVersion: UInt
    public let installationID: UUID
    public let revision: UInt64
    public let keyID: UUID
    public let nonce: Data
    public var ciphertext: Data
    public let tag: Data

    public init(
        formatVersion: UInt,
        installationID: UUID,
        revision: UInt64,
        keyID: UUID,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) {
        self.formatVersion = formatVersion
        self.installationID = installationID
        self.revision = revision
        self.keyID = keyID
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }
}

private struct VaultAuthenticatedHeader: Codable {
    let formatVersion: UInt
    let installationID: UUID
    let revision: UInt64
    let keyID: UUID
}

public actor EncryptedVault {
    public static let currentFormatVersion: UInt = 1

    private let fileURL: URL
    private let keyStore: any VaultKeyStore

    public init(fileURL: URL, keyStore: any VaultKeyStore) {
        self.fileURL = fileURL
        self.keyStore = keyStore
    }

    @discardableResult
    public func initialize(
        document: VaultDocument,
        installationID: UUID = UUID()
    ) async throws -> VaultEnvelope {
        guard !FileManager.default.fileExists(atPath: fileURL.path) else {
            throw VaultError.alreadyInitialized
        }

        let keyID = UUID()
        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        try await keyStore.storeKey(keyData, id: keyID)
        let envelope = try seal(
            document: document,
            installationID: installationID,
            revision: 1,
            keyID: keyID,
            key: key
        )
        try persist(envelope)
        try await keyStore.storeRevision(1, installationID: installationID)
        return envelope
    }

    public func load() async throws -> VaultDocument {
        let envelope = try readEnvelope()
        guard envelope.formatVersion == Self.currentFormatVersion else {
            throw VaultError.unsupportedFormat
        }

        let marker = try await keyStore.loadRevision(installationID: envelope.installationID)
        if let marker, envelope.revision < marker {
            throw VaultError.rollbackDetected
        }
        guard let keyData = try await keyStore.loadKey(id: envelope.keyID) else {
            throw VaultError.keyUnavailable
        }

        let document = try open(envelope: envelope, key: SymmetricKey(data: keyData))
        if marker.map({ envelope.revision > $0 }) ?? true {
            try await keyStore.storeRevision(
                envelope.revision,
                installationID: envelope.installationID
            )
        }
        return document
    }

    @discardableResult
    public func update(document: VaultDocument) async throws -> VaultEnvelope {
        _ = try await load()
        let current = try readEnvelope()
        guard let keyData = try await keyStore.loadKey(id: current.keyID) else {
            throw VaultError.keyUnavailable
        }
        let nextRevision = current.revision + 1
        let next = try seal(
            document: document,
            installationID: current.installationID,
            revision: nextRevision,
            keyID: current.keyID,
            key: SymmetricKey(data: keyData)
        )
        try persist(next)
        try await keyStore.storeRevision(nextRevision, installationID: current.installationID)
        return next
    }

    private func seal(
        document: VaultDocument,
        installationID: UUID,
        revision: UInt64,
        keyID: UUID,
        key: SymmetricKey
    ) throws -> VaultEnvelope {
        let header = VaultAuthenticatedHeader(
            formatVersion: Self.currentFormatVersion,
            installationID: installationID,
            revision: revision,
            keyID: keyID
        )
        let plaintext = try Self.encoder().encode(document)
        let authenticatedData = try Self.encoder().encode(header)
        let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: authenticatedData)
        return VaultEnvelope(
            formatVersion: Self.currentFormatVersion,
            installationID: installationID,
            revision: revision,
            keyID: keyID,
            nonce: Data(sealed.nonce),
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
    }

    private func open(envelope: VaultEnvelope, key: SymmetricKey) throws -> VaultDocument {
        let header = VaultAuthenticatedHeader(
            formatVersion: envelope.formatVersion,
            installationID: envelope.installationID,
            revision: envelope.revision,
            keyID: envelope.keyID
        )
        do {
            let nonce = try AES.GCM.Nonce(data: envelope.nonce)
            let box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: envelope.ciphertext,
                tag: envelope.tag
            )
            let plaintext = try AES.GCM.open(
                box,
                using: key,
                authenticating: Self.encoder().encode(header)
            )
            return try Self.decoder().decode(VaultDocument.self, from: plaintext)
        } catch {
            throw VaultError.authenticationFailed
        }
    }

    private func readEnvelope() throws -> VaultEnvelope {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            throw VaultError.notInitialized
        }
        do {
            return try Self.decoder().decode(VaultEnvelope.self, from: Data(contentsOf: fileURL))
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError.authenticationFailed
        }
    }

    private func persist(_ envelope: VaultEnvelope) throws {
        do {
            try FileManager.default.createDirectory(
                at: fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try Self.encoder().encode(envelope).write(to: fileURL, options: .atomic)
        } catch {
            throw VaultError.persistenceFailed
        }
    }

    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    private static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

extension EncryptedVault: VaultDocumentStoring {
    public func readDocument() async throws -> VaultDocument {
        try await load()
    }

    public func writeDocument(_ document: VaultDocument) async throws {
        _ = try await update(document: document)
    }
}
