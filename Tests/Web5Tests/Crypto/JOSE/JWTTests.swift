import XCTest
import AnyCodable

@testable import Web5

final class JWTTests: XCTestCase {
    
    func test_sign() throws {
        let did = try DIDJWK.create()

        let claims = JWT.Claims(
            issuer: did.identifier,
            expiration: Date.distantFuture,
            misc: ["nonce": AnyCodable(Date.now.hashValue)]
        )
        let jwt = try JWT.sign(did: did, claims: claims)

        XCTAssertFalse(jwt.isEmpty)
        
        let decoded = try JWT.parse(jwtString: jwt)
        if let nonceValue = decoded.payload.miscellaneous?["foo"]?.value as? String {
            print("Nonce value: \(nonceValue)")
        } else {
            print("Nonce value not found")
        }
    }
}

class JWTClaimsTests: XCTestCase {

    func testClaimsEncodingDecoding() {
        let originalClaims = JWT.Claims(
            issuer: "issuer",
            subject: "subject",
            audience: "audience",
            expiration: Date(timeIntervalSince1970: 10000),
            notBefore: Date(timeIntervalSince1970: 5000),
            issuedAt: Date(timeIntervalSince1970: 0),
            jwtID: "jwtID",
            misc: ["foo": AnyCodable("bar")]
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970

        do {
            let encodedData = try encoder.encode(originalClaims)
            let decodedClaims = try decoder.decode(JWT.Claims.self, from: encodedData)

            XCTAssertEqual(originalClaims.issuer, decodedClaims.issuer)
            XCTAssertEqual(originalClaims.subject, decodedClaims.subject)
            XCTAssertEqual(originalClaims.audience, decodedClaims.audience)
            XCTAssertEqual(originalClaims.expiration, decodedClaims.expiration)
            XCTAssertEqual(originalClaims.notBefore, decodedClaims.notBefore)
            XCTAssertEqual(originalClaims.issuedAt, decodedClaims.issuedAt)
            XCTAssertEqual(originalClaims.jwtID, decodedClaims.jwtID)
            
            // Log and compare custom claims
            let originalMiscValue = originalClaims.miscellaneous?["foo"]?.value as? String
            let decodedMiscValue = decodedClaims.miscellaneous?["foo"]?.value as? String

            if let originalMiscValue = originalMiscValue, let decodedMiscValue = decodedMiscValue {
                XCTAssertEqual(originalMiscValue, decodedMiscValue, "Misc claims did not match.")
            } else {
                XCTFail("Custom claims could not be found or did not match. Original: \(String(describing: originalMiscValue)), Decoded: \(String(describing: decodedMiscValue))")
            }

        } catch {
            XCTFail("Encoding or decoding failed with error: \(error)")
        }
    }
}
