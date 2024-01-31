import XCTest

@testable import Web5

final class InMemoryKeyManagerTests: XCTestCase {

    let keyManager = InMemoryKeyManager()
    let payload = "Hello, world!".data(using: .utf8)!

    func test_generatePrivateKey() {
        // All algorithms should be able to successfully generate a private key in the key manager
        for algorithm in CryptoAlgorithm.allCases {
            XCTAssertNoThrow(try keyManager.generatePrivateKey(algorithm: algorithm))
        }
    }

    func test_getPublicKey_privateKeyInStore() throws {
        // All algorithms should be able to retrieve a public key from the alias provided when generating a private key
        for algorithm in CryptoAlgorithm.allCases {
            let keyAlias = try keyManager.generatePrivateKey(algorithm: algorithm)

            do {
                let publicKey = try keyManager.getPublicKey(keyAlias: keyAlias)
                XCTAssertNotNil(publicKey)
            } catch {
                XCTFail("Failed to retrieve public key: \(error)")
            }
        }
    }

    func test_getPublicKey_privateKeyNotInStore() throws {
        // When a private key is not in the store for the provided alias, an error should be thrown
        XCTAssertThrowsError(try keyManager.getPublicKey(keyAlias: "keyAliasNotInStore")) { error in
            guard let error = error as? LocalKeyManager.Error,
                case .keyNotFound = error
            else {
                return XCTFail("Expected LocalKeyManager.Error.keyNotFound, but got \(error)")
            }
        }
    }

    func test_sign() throws {
        // All algorithms should be able to sign a payload with a private key in the key manager
        for algorithm in CryptoAlgorithm.allCases {
            let keyAlias = try keyManager.generatePrivateKey(algorithm: algorithm)
            XCTAssertNoThrow(try keyManager.sign(keyAlias: keyAlias, payload: payload))
        }
    }

    func test_sign_keyAliasNotInStore() throws {
        // When the provided `keyAlias` is not in the store, an error should be thrown
        XCTAssertThrowsError(try keyManager.sign(keyAlias: "InvalidAlias", payload: payload))
    }

    func test_getDeterministicAlias() throws {
        // All algorithms should be able to generate a deterministic alias from a public key,
        // and that alias should match what was returned when generating a private key.
        for algorithm in CryptoAlgorithm.allCases {
            let keyAlias = try keyManager.generatePrivateKey(algorithm: algorithm)
            let publicKey = try keyManager.getPublicKey(keyAlias: keyAlias)

            do {
                let defaultAlias = try keyManager.getDeterministicAlias(key: publicKey)
                XCTAssertEqual(keyAlias, defaultAlias)
            } catch {
                XCTFail("Failed to retrieve deterministic alias: \(error)")
            }
        }
    }
}
