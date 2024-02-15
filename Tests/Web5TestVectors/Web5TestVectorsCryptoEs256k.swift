import CustomDump
import XCTest

@testable import Web5

final class Web5TestVectorsCryptoEs256k: XCTestCase {

    func test_sign() throws {
        /// Input data format for `sign` test vectors
        struct Input: Codable {
            let data: String
            let key: Jwk
        }

        let testVector = try TestVector<Input, String>(
            fileName: "sign",
            subdirectory: "test-vectors/crypto_es256k"
        )

        testVector.run { vector in
            let vectorBlock = {
                let signature = try Secp256k1.sign(
                    payload: try XCTUnwrap(Data.fromHexString(vector.input.data)),
                    privateKey: vector.input.key
                )
                XCTAssertNoDifference(signature.toHexString(), vector.output)
            }

            if vector.errors ?? false {
                XCTAssertThrowsError(try vectorBlock())
            } else {
                XCTAssertNoThrow(try vectorBlock())
            }
        }
    }

    func test_verify() throws {
        /// Input data format for `verify` test vectors
        struct Input: Codable {
            let data: String
            let key: Jwk
            let signature: String
        }

        let testVector = try TestVector<Input, Bool>(
            fileName: "verify",
            subdirectory: "test-vectors/crypto_es256k"
        )

        testVector.run { vector in
            let vectorBlock = {
                let result = try Secp256k1.verify(
                    payload: try XCTUnwrap(Data.fromHexString(vector.input.data)),
                    signature: try XCTUnwrap(Data.fromHexString(vector.input.signature)),
                    publicKey: vector.input.key
                )
                XCTAssertNoDifference(result, vector.output)
            }

            if vector.errors ?? false {
                XCTAssertThrowsError(try vectorBlock())
            } else {
                XCTAssertNoThrow(try vectorBlock())
            }
        }
    }

}
