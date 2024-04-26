import XCTest

@testable import Web5

final class DIDResolverTests: XCTestCase {

    func test_invalidDid() async {
        let didResolutionResult = await DIDResolver.resolve(didURI: "unparseable:did");
        XCTAssertNotNil(didResolutionResult)
        XCTAssertNotNil(didResolutionResult.didResolutionMetadata)
        XCTAssertNil(didResolutionResult.didDocument)
        XCTAssertNotNil(didResolutionResult.didDocumentMetadata)
        XCTAssertEqual(didResolutionResult.didResolutionMetadata.error, DIDResolutionResult.Error.invalidDID.rawValue)
    }

    func test_methodNotSupport() async {
        let didResolutionResult = await DIDResolver.resolve(didURI: "did:unknown:abc123");
        XCTAssertNotNil(didResolutionResult)
        XCTAssertNotNil(didResolutionResult.didResolutionMetadata)
        XCTAssertNil(didResolutionResult.didDocument)
        XCTAssertNotNil(didResolutionResult.didDocumentMetadata)
        XCTAssertEqual(didResolutionResult.didResolutionMetadata.error, DIDResolutionResult.Error.methodNotSupported.rawValue)
    }

    func test_invalidDidUrlDereference() async {
        let result = await DIDResolver.dereference(didUrl: "abcd123;;;")
        XCTAssertNil(result.contentStream)
        XCTAssertNotNil(result.dereferencingMetadata.error)
        XCTAssertEqual(result.dereferencingMetadata.error, DID.Error.invalidURI.localizedDescription)
    }

    func test_invalidDidDereference() async {
        let result = await DIDResolver.dereference(didUrl: "did:jwk:abcd123")
        XCTAssertNil(result.contentStream)
        XCTAssertNotNil(result.dereferencingMetadata.error)
        XCTAssertEqual(result.dereferencingMetadata.error, DIDResolutionResult.Error.invalidDIDDocument.rawValue)
    }
    
    func test_dereferenceVerificationMethod() async {
        let did = try! DIDJWK.create()
        let result = await DIDResolver.dereference(didUrl: did.document.verificationMethod![0].id)
        XCTAssertNotNil(result.contentStream)
        XCTAssertNil(result.dereferencingMetadata.error)
        XCTAssertTrue(DIDUtility.isDidVerificationMethod(obj: result.contentStream!.value))
    }

}