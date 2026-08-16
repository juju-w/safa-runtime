import Foundation
import SAFACrypto
import Security
import Testing

@Suite("Data-protection Keychain query contract")
struct KeychainIntegrationTests {
    @Test("queries are non-synchronizing and this-device-only")
    func secureAccessClass() throws {
        let locator = OpaqueKeychainLocator(id: UUID())
        let query = DataProtectionKeychainStore.baseQuery(for: locator)

        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(
            query[kSecAttrAccessible as String] as? String
                == (kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        )
        #expect(locator.account.hasPrefix("safa.credential."))
        #expect(!(query.values.compactMap { $0 as? String }).contains("nas.home"))
    }
}
