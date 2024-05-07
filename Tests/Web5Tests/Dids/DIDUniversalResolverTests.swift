import XCTest

@testable import Web5

final class DIDUniversalResolverTests: XCTestCase {

    var universalResolver = DIDUniversalResolver()
    
    func test_invalidDid() async {
        let didResolutionResult = await universalResolver.resolve(didURI: "unparseable:did");
        XCTAssertNotNil(didResolutionResult)
        XCTAssertNotNil(didResolutionResult.didResolutionMetadata)
        XCTAssertNil(didResolutionResult.didDocument)
        XCTAssertNotNil(didResolutionResult.didDocumentMetadata)
        XCTAssertEqual(didResolutionResult.didResolutionMetadata.error, DIDResolutionResult.Error.invalidDID.rawValue)
    }

    func test_methodNotSupport() async {
        let didResolutionResult = await universalResolver.resolve(didURI: "did:unknown:abc123");
        XCTAssertNotNil(didResolutionResult)
        XCTAssertNotNil(didResolutionResult.didResolutionMetadata)
        XCTAssertNil(didResolutionResult.didDocument)
        XCTAssertNotNil(didResolutionResult.didDocumentMetadata)
        XCTAssertEqual(didResolutionResult.didResolutionMetadata.error, DIDResolutionResult.Error.methodNotSupported.rawValue)
    }

    func test_invalidDidUrlDereference() async {
        let result = await universalResolver.dereference(didUrl: "abcd123;;;")
        XCTAssertNil(result.contentStream)
        XCTAssertNotNil(result.dereferencingMetadata.error)
        XCTAssertEqual(result.dereferencingMetadata.error, DID.Error.invalidURI.localizedDescription)
    }

    func test_invalidDidDereference() async {
        let result = await universalResolver.dereference(didUrl: "did:jwk:abcd123")
        XCTAssertNil(result.contentStream)
        XCTAssertNotNil(result.dereferencingMetadata.error)
        XCTAssertEqual(result.dereferencingMetadata.error, DIDResolutionResult.Error.invalidDIDDocument.rawValue)
    }
    
    func test_dereferenceVerificationMethodAsDIDResource() async {
        let did = try! DIDJWK.create()
        let result = await universalResolver.dereference(didUrl: did.document.verificationMethod![0].id)
        XCTAssertNotNil(result.contentStream)
        XCTAssertNil(result.dereferencingMetadata.error)
        XCTAssertTrue(DIDUtility.isDidVerificationMethod(obj: result.contentStream!.value))
    }

    func test_dereferenceServiceAsDIDResource() async {

        struct MockResolver: DIDURIResolve {
            static let service = Service(id: "#dwn", 
                                                  type: "DecentralizedWebNode", 
                                                  serviceEndpoint: OneOrMany("https://dwn.tbddev.test/dwn0"))
            func resolve(didURI: String, options: DidResolutionOptions?) async -> DIDResolutionResult {
                var mockDidDocument = DIDDocument(id: "did:example:123456789abcdefghi")
                mockDidDocument.service = [MockResolver.service]
                
                return DIDResolutionResult(didResolutionMetadata: DIDResolutionResult.Metadata(),
                                            didDocument: mockDidDocument, 
                                            didDocumentMetadata: DIDDocument.Metadata())
            }
        }

        let dereferencer = DIDUniversalResolver.DIDDereferencer(resolver: MockResolver())
        let universalResolver = DIDUniversalResolver(dereferencer: dereferencer)
        let result = await universalResolver.dereference(didUrl: "did:example:123456789abcdefghi#dwn")

        XCTAssertNotNil(result.contentStream)
        let resource = result.contentStream!.value as! Service
        XCTAssertEqual(resource, MockResolver.service)
    }

    func test_dereferenceDIDNoFragment() async {
        let did = try! DIDJWK.create()
        let result = await universalResolver.dereference(didUrl: did.uriWithoutFragment)
        XCTAssertNotNil(result.contentStream)
        XCTAssertNil(result.dereferencingMetadata.error)
        let resource = result.contentStream!.value as! DIDDocument
        XCTAssertNotNil(resource.context)
        let listElement = DIDDocument.Context.ListElement.string("https://www.w3.org/ns/did/v1")
        XCTAssertEqual(resource.context, DIDDocument.Context.list([listElement]))
    }

    func test_dereferencenotFoundContentStream() async {
        let did = try! DIDJWK.create()
        let uri = "\(did.uriWithoutFragment)#1"
        let result = await universalResolver.dereference(didUrl: uri)
        XCTAssertNil(result.contentStream)
        XCTAssertNotNil(result.dereferencingMetadata.error)
        XCTAssertEqual(result.dereferencingMetadata.error, DID.Error.notFound.localizedDescription)
    }

    func testRegisterResolver() async {

        struct MockResolver: DIDMethodResolver {
            public let methodName = "mock"
            public func resolve(didURI: String) async -> DIDResolutionResult {
                let metaData = DIDResolutionResult.Metadata(contentType: "this is mock resolver")
                return DIDResolutionResult(didResolutionMetadata: metaData)
            }
        }

        DIDUniversalResolver.register(resolver: MockResolver())
        let result = await universalResolver.resolve(didURI: "did:mock:abc123")
        XCTAssertEqual(result.didResolutionMetadata.contentType, "this is mock resolver")
    }
}