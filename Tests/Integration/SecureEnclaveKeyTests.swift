import Foundation
import SAFACrypto
import Security
import Testing

@Suite("Secure Enclave SSH key lifecycle")
struct SecureEnclaveKeyTests {
    @Test("P-256 enrollment is device-bound when the platform supports it")
    func lifecycle() throws {
        #expect(
            SecureEnclaveSSHKey.privateKeyAttributes(id: UUID())[kSecAttrIsPermanent as String]
                as? Bool == true)
        guard SecureEnclaveSSHKey.isAvailable else { return }

        let key: SecureEnclaveSSHKey
        do {
            key = try SecureEnclaveSSHKey.create(label: "SAFA synthetic test")
        } catch SecureEnclaveSSHKeyError.creationFailed {
            // Unsigned SwiftPM test bundles cannot always obtain Secure Enclave keychain access.
            return
        }
        defer { try? key.delete() }
        #expect(key.openSSHPublicKey.hasPrefix("ecdsa-sha2-nistp256 "))
        #expect(!key.openSSHPublicKey.contains("PRIVATE"))
        #expect(!key.locator.account.contains("nas.home"))
    }
}
