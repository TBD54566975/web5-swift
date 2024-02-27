import XCTest

@testable import Web5

final class JWSTests: XCTestCase {

    let did = try! DIDJWK.create(keyManager: InMemoryKeyManager())
    let payload = "Hello, World!".data(using: .utf8)!

    func test_sign_detachedPayload() throws {
        let compactJWS = try JWS.sign(did: did, payload: payload, options: .init(detached: true))
        let compactJWSParts = compactJWS.split(separator: ".", omittingEmptySubsequences: false)

        XCTAssertEqual(compactJWSParts.count, 3)
        // Payload (second part) should be empty, as the payload is detached
        XCTAssertTrue(compactJWSParts[1].isEmpty)
    }

    func test_sign_attachedPayload() throws {
        let compactJWS = try JWS.sign(did: did, payload: payload, options: .init(detached: false))
        let compactJWSParts = compactJWS.split(separator: ".", omittingEmptySubsequences: false)

        XCTAssertEqual(compactJWSParts.count, 3)
        // Payload (second part) should NOT be empty, as the payload is attached
        XCTAssertFalse(compactJWSParts[1].isEmpty)
    }

    func test_verify_detachedPayload() async throws {
        let compactJWS = try JWS.sign(did: did, payload: payload, options: .init(detached: true))
        let isValid = try await JWS.verify(compactJWS: compactJWS, detachedPayload: payload)

        XCTAssertTrue(isValid)
    }

    func test_verify_attachedPayload() async throws {
        let compactJWS = try JWS.sign(did: did, payload: payload, options: .init(detached: false))
        let isValid = try await JWS.verify(compactJWS: compactJWS)

        XCTAssertTrue(isValid)
    }

    func test_verify_expectedSigningDIDURI_match() async throws {
        let compactJWS = try JWS.sign(did: did, payload: payload, options: .init(detached: false))
        let isValid = try await JWS.verify(compactJWS: compactJWS, expectedSigningDIDURI: did.uri)

        XCTAssertTrue(isValid)
    }

    func test_verify_expectedSigningDIDURI_noMatch() async throws {
        let compactJWS = try JWS.sign(did: did, payload: payload, options: .init(detached: false))
        let isValid = try await JWS.verify(compactJWS: compactJWS, expectedSigningDIDURI: "did:example:1234")

        // compactJWS was signed by `did`, but we're expecting it to be signed by a different DID.
        // This should result in an invalid signature.
        XCTAssertFalse(isValid)
    }
}
