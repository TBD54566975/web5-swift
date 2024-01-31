import XCTest

@testable import Web5

final class DIDDocumentTests: XCTestCase {

    func test_embeddedVerifiationMethod() {
        let value = EmbeddedOrReferencedVerificationMethod.embedded(TestData.verificationMethod)
        XCTAssertEqual(value.dereferenced(with: TestData.didDocument), TestData.verificationMethod)
    }

    func test_referencedVerificationMethod_absoluteURIString() {
        let value = EmbeddedOrReferencedVerificationMethod.referenced("did:example:123456789abcdefghi#key-1")
        XCTAssertEqual(value.dereferenced(with: TestData.didDocument), TestData.verificationMethod)
    }

    func test_referencedVerificationMethod_fragmentString() {
        let value = EmbeddedOrReferencedVerificationMethod.referenced("#key-1")
        XCTAssertEqual(value.dereferenced(with: TestData.didDocument), TestData.verificationMethod)
    }

}

private enum TestData {

    static let verificationMethod = VerificationMethod(
        id: "did:example:123456789abcdefghi#key-1",
        type: "type",
        controller: "did:example:123456789abcdefghi"
    )

    static let didDocument = DIDDocument(
        id: "did:example:123456789abcdefghi",
        verificationMethod: [Self.verificationMethod]
    )

}
