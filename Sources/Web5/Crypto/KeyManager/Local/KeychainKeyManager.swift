import Foundation
import Security

/// A KeyManager that generates and stores cryptographic keys in the Keychain
public class KeychainKeyManager: LocalKeyManager {

    public init() {
        super.init(keyStore: KeychainKeyStore())
    }
}

class KeychainKeyStore: LocalKeyStore {

    func getKey(keyAlias: String) throws -> Jwk? {
        let keychainQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationLabel as String: keyAlias,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(keychainQuery as CFDictionary, &item)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return nil
            } else {
                throw NSError(
                    domain: NSOSStatusErrorDomain,
                    code: Int(status),
                    userInfo: [
                        NSLocalizedDescriptionKey: "Failed to fetch key for alias \(keyAlias) from KeychainKeyStore"
                    ]
                )
            }
        }

        guard let data = item as? Data else {
            return nil
        }

        let jwk = try JSONDecoder().decode(Jwk.self, from: data)
        return jwk
    }

    func setKey(_ privateKey: Jwk, keyAlias: String) throws {
        let dataToStore = try JSONEncoder().encode(privateKey)

        let keychainQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationLabel as String: keyAlias,
            kSecValueData as String: dataToStore
        ]

        let status = SecItemAdd(keychainQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(
                domain: NSOSStatusErrorDomain,
                code: Int(status),
                userInfo: [
                    NSLocalizedDescriptionKey: "Failed to store key for alias \(keyAlias) in KeychainKeyStore"
                ]
            )
        }
    }
}
