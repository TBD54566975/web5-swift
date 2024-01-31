import XCTest

@testable import Web5

final class CryptoTests: XCTestCase {

    let payload = "Hello, World!".data(using: .utf8)!

    func test_generatePrivateKey() {
        // All algorithms should be able to successfully generate a private key
        for algorithm in CryptoAlgorithm.allCases {
            XCTAssertNoThrow(try Crypto.generatePrivateKey(algorithm: algorithm))
        }
    }

    func test_computePublicKey() throws {
        // All algorithms should be able to successfully compute a public key from a private key it generated
        for algorithm in CryptoAlgorithm.allCases {
            let privateKey = try Crypto.generatePrivateKey(algorithm: algorithm)

            XCTAssertNoThrow(try Crypto.computePublicKey(privateKey: privateKey))
        }
    }

    func test_sign() throws {
        // All algorithms should be able to sign a payload with a private key
        for algorithm in CryptoAlgorithm.allCases {
            let privateKey = try Crypto.generatePrivateKey(algorithm: algorithm)

            XCTAssertNoThrow(try Crypto.sign(payload: payload, privateKey: privateKey))
        }
    }

    func test_verify() throws {
        // All algorithms should be able to successfully verify a payload signed with a private key it generated
        for algorithm in CryptoAlgorithm.allCases {
            let privateKey = try Crypto.generatePrivateKey(algorithm: algorithm)
            let publicKey = try Crypto.computePublicKey(privateKey: privateKey)
            let signature = try Crypto.sign(payload: payload, privateKey: privateKey)

            do {
                let isValid = try Crypto.verify(payload: payload, signature: signature, publicKey: publicKey)
                XCTAssertTrue(isValid)
            } catch {
                XCTFail("Failed to verify signature: \(error)")
            }
        }
    }

    func test_verify_invalidWhenSignatureIsFromAnotherAlgorithm() throws {
        // If a signature is generated with a private key from one algorithm,
        // it should not be valid when verified with a public key from another algorithm
        for signingAlgorithm in CryptoAlgorithm.allCases {
            let signingPrivateKey = try Crypto.generatePrivateKey(algorithm: signingAlgorithm)
            let signature = try Crypto.sign(payload: payload, privateKey: signingPrivateKey)

            for verifyingAlgorithm in CryptoAlgorithm.allCases where verifyingAlgorithm != signingAlgorithm {
                let verifyingPrivateKey = try Crypto.generatePrivateKey(algorithm: verifyingAlgorithm)
                let verifyingPublicKey = try Crypto.computePublicKey(privateKey: verifyingPrivateKey)

                do {
                    let isValid = try Crypto.verify(
                        payload: payload,
                        signature: signature,
                        publicKey: verifyingPublicKey
                    )
                    XCTAssertFalse(isValid)
                } catch {
                    XCTFail("Failed to verify signature: \(error)")
                }

            }
        }
    }
}
