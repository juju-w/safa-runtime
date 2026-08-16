import CryptoKit
import Foundation
import Security

public enum SecureEnclaveSSHKeyError: Error, Equatable, Sendable {
    case unavailable
    case creationFailed
    case publicKeyUnavailable
    case deletionFailed
    case signingFailed
}

public final class SecureEnclaveSSHKey: @unchecked Sendable {
    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    public let locator: OpaqueKeychainLocator
    public let openSSHPublicKey: String

    private let privateKey: SecKey
    private let applicationTag: Data

    private init(
        locator: OpaqueKeychainLocator,
        openSSHPublicKey: String,
        privateKey: SecKey,
        applicationTag: Data
    ) {
        self.locator = locator
        self.openSSHPublicKey = openSSHPublicKey
        self.privateKey = privateKey
        self.applicationTag = applicationTag
    }

    public static func privateKeyAttributes(id: UUID) -> [String: Any] {
        let tag = Data("dev.safa.secureenclave.\(id.uuidString.lowercased())".utf8)
        return [
            kSecAttrApplicationTag as String: tag,
            kSecAttrIsPermanent as String: true,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
    }

    public static func create(label: String) throws -> SecureEnclaveSSHKey {
        guard isAvailable else { throw SecureEnclaveSSHKeyError.unavailable }
        let id = UUID()
        var accessError: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .privateKeyUsage,
                &accessError
            )
        else {
            throw SecureEnclaveSSHKeyError.creationFailed
        }
        var privateAttributes = privateKeyAttributes(id: id)
        let tag = privateAttributes[kSecAttrApplicationTag as String] as! Data
        privateAttributes[kSecAttrAccessControl as String] = access
        privateAttributes[kSecAttrLabel as String] = label
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateAttributes,
        ]
        var creationError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &creationError) else {
            throw SecureEnclaveSSHKeyError.creationFailed
        }
        guard
            let publicKey = SecKeyCopyPublicKey(key),
            let representation = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
        else {
            throw SecureEnclaveSSHKeyError.publicKeyUnavailable
        }
        let publicBlob = sshPublicKeyBlob(x963Representation: representation)
        return SecureEnclaveSSHKey(
            locator: OpaqueKeychainLocator(id: id),
            openSSHPublicKey: "ecdsa-sha2-nistp256 \(publicBlob.base64EncodedString())",
            privateKey: key,
            applicationTag: tag
        )
    }

    public func sign(_ message: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard
            let signature = SecKeyCreateSignature(
                privateKey,
                .ecdsaSignatureMessageX962SHA256,
                message as CFData,
                &error
            ) as Data?
        else {
            throw SecureEnclaveSSHKeyError.signingFailed
        }
        return signature
    }

    public func delete() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureEnclaveSSHKeyError.deletionFailed
        }
    }

    private static func sshPublicKeyBlob(x963Representation: Data) -> Data {
        var data = Data()
        data.appendSSHString(Data("ecdsa-sha2-nistp256".utf8))
        data.appendSSHString(Data("nistp256".utf8))
        data.appendSSHString(x963Representation)
        return data
    }
}

private extension Data {
    mutating func appendSSHString(_ value: Data) {
        var length = UInt32(value.count).bigEndian
        Swift.withUnsafeBytes(of: &length) { append(contentsOf: $0) }
        append(value)
    }
}
