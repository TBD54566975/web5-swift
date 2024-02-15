import CustomDump
import XCTest

@testable import Web5

final class Ed25519Tests: XCTestCase {

    let payload = "Hello, World!".data(using: .utf8)!

    func test_generateKey() throws {
        let privateKey = try Ed25519.generatePrivateKey()

        XCTAssertEqual(privateKey.keyType, .octetKeyPair)
        XCTAssertEqual(privateKey.curve, .ed25519)
        XCTAssertNotNil(privateKey.keyID)
        XCTAssertNotNil(privateKey.d)
        XCTAssertNotNil(privateKey.x)
        XCTAssertNil(privateKey.y)

        // Generated private key should always be 32 bytes in length
        let privateKeyBytes = try XCTUnwrap(privateKey.d?.decodeBase64Url())
        XCTAssertEqual(privateKeyBytes.count, 32)
    }

    func test_computePublicKey() throws {
        let privateKey = try Ed25519.generatePrivateKey()
        let publicKey = try Ed25519.computePublicKey(privateKey: privateKey)

        XCTAssertEqual(publicKey.keyType, .octetKeyPair)
        XCTAssertEqual(publicKey.curve, .ed25519)
        XCTAssertNotNil(publicKey.keyID)
        XCTAssertNil(publicKey.d)
        XCTAssertNotNil(publicKey.x)
        XCTAssertNil(publicKey.y)

        XCTAssertEqual(publicKey.curve, privateKey.curve)
        XCTAssertEqual(publicKey.keyType, privateKey.keyType)
        XCTAssertEqual(publicKey.keyID, privateKey.keyID)
        XCTAssertEqual(publicKey.x, privateKey.x)
        XCTAssertEqual(publicKey.y, privateKey.y)
    }

    func test_privateKey_toAndFromBytes() throws {
        let privateKey = try Ed25519.generatePrivateKey()
        let privateKeyBytes = try Ed25519.privateKeyToBytes(privateKey)
        let restoredPrivateKey = try Ed25519.privateKeyFromBytes(privateKeyBytes)

        XCTAssertNoDifference(privateKey, restoredPrivateKey)
    }

    func test_publicKey_toAndFromBytes() throws {
        let privateKey = try Ed25519.generatePrivateKey()
        let publicKey = try Ed25519.computePublicKey(privateKey: privateKey)
        let publicKeyBytes = try Ed25519.publicKeyToBytes(publicKey)
        let restoredPublicKey = try Ed25519.publicKeyFromBytes(publicKeyBytes)

        XCTAssertNoDifference(publicKey, restoredPublicKey)
    }

    func test_sign() throws {
        let privateKey = try Ed25519.generatePrivateKey()
        let signature = try Ed25519.sign(payload: payload, privateKey: privateKey)

        // Signatures should always be 64 bytes in length
        XCTAssertEqual(signature.count, 64)
    }

    func test_sign_errorsWhenPrivateKeyFromAnotherAlgorithm() throws {
        let secp256k1PrivateKey = try Secp256k1.generatePrivateKey()
        XCTAssertThrowsError(try Ed25519.sign(payload: payload, privateKey: secp256k1PrivateKey))
    }

    func test_verify() throws {
        let privateKey = try Ed25519.generatePrivateKey()
        let publickey = try Ed25519.computePublicKey(privateKey: privateKey)
        let signature = try Ed25519.sign(payload: payload, privateKey: privateKey)
        let isValid = try Ed25519.verify(payload: payload, signature: signature, publicKey: publickey)

        XCTAssertTrue(isValid)
    }

    func test_verify_invalidWhenPayloadMutated() throws {
        let privateKey = try Ed25519.generatePrivateKey()
        let publickey = try Ed25519.computePublicKey(privateKey: privateKey)
        let signature = try Ed25519.sign(payload: payload, privateKey: privateKey)

        // Make a copy and flip the least significant bit of the payload
        var mutatedPayload = payload
        mutatedPayload[0] ^= 1 << 0

        // Verification should return false, as the verified payload does not
        // match the payload used to generate the signature
        let isValid = try Ed25519.verify(payload: mutatedPayload, signature: signature, publicKey: publickey)
        XCTAssertFalse(isValid)
    }

    func test_verify_invalidWhenSignatureMutated() throws {
        let privateKey = try Ed25519.generatePrivateKey()
        let publickey = try Ed25519.computePublicKey(privateKey: privateKey)
        let signature = try Ed25519.sign(payload: payload, privateKey: privateKey)

        // Make a copy and flip the least significant bit of the signature
        var mutatedSignature = signature
        mutatedSignature[0] ^= 1 << 0

        // Verification should return false, as the signature for the payload has been mutated
        let isValid = try Ed25519.verify(payload: payload, signature: mutatedSignature, publicKey: publickey)
        XCTAssertFalse(isValid)
    }
}
