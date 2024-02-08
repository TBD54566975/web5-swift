import CustomDump
import XCTest

@testable import Web5

final class ECDSA_Es256kTests: XCTestCase {

    let payload = "Hello, World!".data(using: .utf8)!

    func test_generatePrivateKey() throws {
        let privateKey = try ECDSA.Es256k.generatePrivateKey()

        XCTAssertEqual(privateKey.curve, .secp256k1)
        XCTAssertEqual(privateKey.keyType, .elliptic)
        XCTAssertNotNil(privateKey.keyID)
        XCTAssertNotNil(privateKey.d)
        XCTAssertNotNil(privateKey.x)
        XCTAssertNotNil(privateKey.y)
    }

    func test_computePublicKey() throws {
        let privateKey = try ECDSA.Es256k.generatePrivateKey()
        let publicKey = try ECDSA.Es256k.computePublicKey(privateKey: privateKey)

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
        let privateKey = try ECDSA.Es256k.generatePrivateKey()
        let privateKeyBytes = try ECDSA.Es256k.privateKeyToBytes(privateKey)
        let restoredPrivateKey = try ECDSA.Es256k.privateKeyFromBytes(privateKeyBytes)

        XCTAssertNoDifference(privateKey, restoredPrivateKey)
    }

    func test_publicKey_toAndFromBytes() throws {
        let privateKey = try ECDSA.Es256k.generatePrivateKey()
        let publicKey = try ECDSA.Es256k.computePublicKey(privateKey: privateKey)
        let publicKeyBytes = try ECDSA.Es256k.publicKeyToBytes(publicKey)
        let restoredPublicKey = try ECDSA.Es256k.publicKeyFromBytes(publicKeyBytes)

        XCTAssertNoDifference(publicKey, restoredPublicKey)
    }

    func test_sign() throws {
        let privateKey = try ECDSA.Es256k.generatePrivateKey()
        let signature = try ECDSA.Es256k.sign(payload: payload, privateKey: privateKey)

        /// Signatures should always be 64 bytes in length
        XCTAssertEqual(signature.count, 64)
    }

    func test_sign_errorsWhenPrivateKeyFromAnotherAlgorithm() throws {
        let ed25519PrivateKey = try EdDSA.Ed25519.generatePrivateKey()
        XCTAssertThrowsError(try ECDSA.Es256k.sign(payload: payload, privateKey: ed25519PrivateKey))
    }

    func test_verify() throws {
        let privateKey = try ECDSA.Es256k.generatePrivateKey()
        let publickey = try ECDSA.Es256k.computePublicKey(privateKey: privateKey)
        let signature = try ECDSA.Es256k.sign(payload: payload, privateKey: privateKey)
        let isValid = try ECDSA.Es256k.verify(payload: payload, signature: signature, publicKey: publickey)

        XCTAssertTrue(isValid)
    }

    func test_verify_invalidWhenPayloadMutated() throws {
        let privateKey = try ECDSA.Es256k.generatePrivateKey()
        let publickey = try ECDSA.Es256k.computePublicKey(privateKey: privateKey)
        let signature = try ECDSA.Es256k.sign(payload: payload, privateKey: privateKey)

        // Make a copy and flip the least significant bit of the payload
        var mutatedPayload = payload
        mutatedPayload[0] ^= 1 << 0

        // Verification should return false, as the verified payload does not
        // match the payload used to generate signature
        let isValid = try ECDSA.Es256k.verify(payload: mutatedPayload, signature: signature, publicKey: publickey)
        XCTAssertFalse(isValid)
    }

    func test_verify_invalidWhenSignatureMutated() throws {
        let privateKey = try ECDSA.Es256k.generatePrivateKey()
        let publickey = try ECDSA.Es256k.computePublicKey(privateKey: privateKey)
        let signature = try ECDSA.Es256k.sign(payload: payload, privateKey: privateKey)

        // Make a copy and flip the least significant bit of the signature
        var mutatedSignature = Data(signature)
        mutatedSignature[0] ^= 1 << 0

        // Verification should return false, as the signature for the payload has been mutated
        let isValid = try ECDSA.Es256k.verify(payload: payload, signature: mutatedSignature, publicKey: publickey)
        XCTAssertFalse(isValid)
    }
}
