import XCTest

@testable import Web5

final class JWTTests: XCTestCase {
    
    func test_sign() throws {
        let did = try DIDJWK.create(keyManager: InMemoryKeyManager())

        let claims = JWT.Claims(issuer: did.identifier)
        let jwt = try JWT.sign(did: did, claims: claims)

        XCTAssertFalse(jwt.isEmpty)
    }
}
