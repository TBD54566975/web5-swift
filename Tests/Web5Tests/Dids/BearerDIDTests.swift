import CustomDump
import XCTest

@testable import Web5

final class BearerDIDTests: XCTestCase {

    func test_export() throws {
        let didJWK = try DIDJWK.create()
        let portableDID = try didJWK.export()

        XCTAssertNoDifference(portableDID.uri, didJWK.uri)
        XCTAssertNoDifference(portableDID.document, didJWK.document)
        XCTAssertNoDifference(portableDID.privateKeys.count, 1)
        XCTAssertNil(portableDID.metadata)
    }

    func test_getSigner() throws {
        let payload = "Hello, world!".data(using: .utf8)!

        let didJWK = try DIDJWK.create()
        let signer = try didJWK.getSigner()

        let signature = try signer.sign(payload: payload)
        let isValid = try signer.verify(payload: payload, signature: signature)

        XCTAssertTrue(isValid)
    }

    func test_getSigner_verificationMethodID() throws {
        let payload = "Hello, world!".data(using: .utf8)!

        let didJWK = try DIDJWK.create()
        let verificationMethodID = try XCTUnwrap(didJWK.document.verificationMethod?.first?.id)

        let signer = try didJWK.getSigner(verificationMethodID: verificationMethodID)
        let signature = try signer.sign(payload: payload)
        let isValid = try signer.verify(payload: payload, signature: signature)

        XCTAssertTrue(isValid)
    }

    func test_getSigner_invalidVerificationMethodID() throws {
        let didJWK = try DIDJWK.create()
        XCTAssertThrowsError(try didJWK.getSigner(verificationMethodID: "not-real"))
    }
}
