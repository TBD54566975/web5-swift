import XCTest

@testable import Web5

final class DIDResourceTests: XCTestCase {

    func test_decodeVerificationMethodAsDIDResource() async {
        let resource = DIDResource.verificationMethod(DIDResourceTests.verificationMethod)
        let encodedData = try! JSONEncoder().encode(resource)
        let decoded = try! JSONDecoder().decode(DIDResource.self, from: encodedData)
        XCTAssertEqual(decoded, resource)
    }

    func test_decodeServiceAsDIDResource() async {
        let resource = DIDResource.service(DIDResourceTests.service)
        let encodedData = try! JSONEncoder().encode(resource)
        let decoded = try! JSONDecoder().decode(DIDResource.self, from: encodedData)
        XCTAssertEqual(decoded, resource)
    }

    func test_decodeDIDDocument() async {
        let did = try! DIDJWK.create()
        let didDocument = await DIDUniversalResolver.DIDResolver().resolve(didURI: did.uri).didDocument
        let resource = DIDResource.didDocument(didDocument!)
        let encoded = try! JSONEncoder().encode(didDocument)
        let decoded = try! JSONDecoder().decode(DIDResource.self, from: encoded)
        XCTAssertEqual(decoded, resource)
    }

    func test_decodeTypeDismatch() async {
        let did = "did:jwk:abc123".data(using: .utf8)!
        XCTAssertThrowsError(try JSONDecoder().decode(DIDResource.self, from: did))
    }

}

extension DIDResourceTests {

    static let verificationMethod = VerificationMethod(
        id: "did:jwk:eyJrdHkiOiJPS1AiLCJraWQiOiJIRW5NemZUellzNFdodGdlQjZuV1hJNlNMLWVrRmF2THRXWmlSd3FlVGswIiwieCI6Ik1MenBFZFM0cTVjSS1oVEtzX0UyZFBtRGMtdURCZGpyY2l0N2tJbFFXUlEiLCJjcnYiOiJFZDI1NTE5IiwiYWxnIjoiRWREU0EifQ#0", 
        type: "JsonWebKey", 
        controller: "did:jwk:eyJrdHkiOiJPS1AiLCJraWQiOiJIRW5NemZUellzNFdodGdlQjZuV1hJNlNMLWVrRmF2THRXWmlSd3FlVGswIiwieCI6Ik1MenBFZFM0cTVjSS1oVEtzX0UyZFBtRGMtdURCZGpyY2l0N2tJbFFXUlEiLCJjcnYiOiJFZDI1NTE5IiwiYWxnIjoiRWREU0EifQ"
    )

    static let service = Service(
        id: "#dwn", 
        type: "DecentralizedWebNode", 
        serviceEndpoint: OneOrMany("https://dwn.tbddev.test/dwn0")
    )
}