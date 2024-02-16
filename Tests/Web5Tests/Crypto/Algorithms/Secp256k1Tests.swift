import CustomDump
import XCTest

@testable import Web5

final class Secp256k1Tests: XCTestCase {

    let payload = "Hello, World!".data(using: .utf8)!

    func test_generatePrivateKey() throws {
        let privateKey = try Secp256k1.generatePrivateKey()

        XCTAssertEqual(privateKey.curve, .secp256k1)
        XCTAssertEqual(privateKey.keyType, .elliptic)
        XCTAssertNotNil(privateKey.keyID)
        XCTAssertNotNil(privateKey.d)
        XCTAssertNotNil(privateKey.x)
        XCTAssertNotNil(privateKey.y)
    }

    func test_computePublicKey() throws {
        let privateKey = try Secp256k1.generatePrivateKey()
        let publicKey = try Secp256k1.computePublicKey(privateKey: privateKey)

        XCTAssertEqual(publicKey.curve, .secp256k1)
        XCTAssertEqual(publicKey.keyType, .elliptic)
        XCTAssertNotNil(publicKey.keyID)
        XCTAssertNil(publicKey.d)
        XCTAssertNotNil(publicKey.x)
        XCTAssertNotNil(publicKey.y)

        XCTAssertEqual(publicKey.curve, privateKey.curve)
        XCTAssertEqual(publicKey.keyType, privateKey.keyType)
        XCTAssertEqual(publicKey.keyID, privateKey.keyID)
        XCTAssertEqual(publicKey.x, privateKey.x)
        XCTAssertEqual(publicKey.y, privateKey.y)
    }

    func test_privateKey_toAndFromBytes() throws {
        let privateKey = try Secp256k1.generatePrivateKey()
        let privateKeyBytes = try Secp256k1.privateKeyToBytes(privateKey)
        let restoredPrivateKey = try Secp256k1.privateKeyFromBytes(privateKeyBytes)

        XCTAssertNoDifference(privateKey, restoredPrivateKey)
    }

    func test_publicKey_toAndFromBytes() throws {
        let privateKey = try Secp256k1.generatePrivateKey()
        let publicKey = try Secp256k1.computePublicKey(privateKey: privateKey)
        let publicKeyBytes = try Secp256k1.publicKeyToBytes(publicKey)
        let restoredPublicKey = try Secp256k1.publicKeyFromBytes(publicKeyBytes)

        XCTAssertNoDifference(publicKey, restoredPublicKey)
    }

    func test_sign() throws {
        let privateKey = try Secp256k1.generatePrivateKey()
        let signature = try Secp256k1.sign(payload: payload, privateKey: privateKey)

        /// Signatures should always be 64 bytes in length
        XCTAssertEqual(signature.count, 64)
    }

    func test_sign_errorsWhenPrivateKeyFromAnotherAlgorithm() throws {
        let ed25519PrivateKey = try Ed25519.generatePrivateKey()
        XCTAssertThrowsError(try Secp256k1.sign(payload: payload, privateKey: ed25519PrivateKey))
    }

    func test_verify() throws {
        let privateKey = try Secp256k1.generatePrivateKey()
        let publickey = try Secp256k1.computePublicKey(privateKey: privateKey)
        let signature = try Secp256k1.sign(payload: payload, privateKey: privateKey)
        let isValid = try Secp256k1.verify(payload: payload, signature: signature, publicKey: publickey)

        XCTAssertTrue(isValid)
    }

    func test_verify_invalidWhenPayloadMutated() throws {
        let privateKey = try Secp256k1.generatePrivateKey()
        let publickey = try Secp256k1.computePublicKey(privateKey: privateKey)
        let signature = try Secp256k1.sign(payload: payload, privateKey: privateKey)

        // Make a copy and flip the least significant bit of the payload
        var mutatedPayload = payload
        mutatedPayload[0] ^= 1 << 0

        // Verification should return false, as the verified payload does not
        // match the payload used to generate signature
        let isValid = try Secp256k1.verify(payload: mutatedPayload, signature: signature, publicKey: publickey)
        XCTAssertFalse(isValid)
    }

    func test_verify_invalidWhenSignatureMutated() throws {
        let privateKey = try Secp256k1.generatePrivateKey()
        let publickey = try Secp256k1.computePublicKey(privateKey: privateKey)
        let signature = try Secp256k1.sign(payload: payload, privateKey: privateKey)

        // Make a copy and flip the least significant bit of the signature
        var mutatedSignature = Data(signature)
        mutatedSignature[0] ^= 1 << 0

        // Verification should return false, as the signature for the payload has been mutated
        let isValid = try Secp256k1.verify(payload: payload, signature: mutatedSignature, publicKey: publickey)
        XCTAssertFalse(isValid)
    }
}
