import XCTest

@testable import Web5

final class DIDJWKTests: XCTestCase {

    func test_create() throws {
        let keyManager = InMemoryKeyManager()
        let didJwk = try DIDJWK.create(keyManager: keyManager)

        XCTAssert(didJwk.uri.starts(with: "did:jwk:"))
    }

    func test_resolveWithError_onInvalidDIDURI() async throws {
        let resolutionResult = await DIDJWK.resolve(didURI: "hi")

        XCTAssertNil(resolutionResult.didDocument)
        XCTAssertEqual(resolutionResult.didResolutionMetadata.error, DIDResolutionResult.Error.invalidDID.rawValue)
    }

    func test_resolveWithError_ifDIDURINotJwk() async {
        let resolutionResult = await DIDJWK.resolve(didURI: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")

        XCTAssertNil(resolutionResult.didDocument)
        XCTAssertEqual(resolutionResult.didResolutionMetadata.error, DIDResolutionResult.Error.invalidDID.rawValue)
    }

    func test_resolveWithError_ifDIDURIIsNotValidBase64Url() async {
        let resolutionResult = await DIDJWK.resolve(didURI: "did:jwk:!!!")

        XCTAssertNil(resolutionResult.didDocument)
        XCTAssertEqual(resolutionResult.didResolutionMetadata.error, DIDResolutionResult.Error.invalidDID.rawValue)
    }

    func test_resolveWithError_ifMethodNotJwk() async {
        let resolutionResult = await DIDJWK.resolve(
            didURI:
                "did:web:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6c2hhLTI1NjpGZk1iek9qTW1RNGVmVDZrdndUSUpqZWxUcWpsMHhqRUlXUTJxb2JzUk1NIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6IkFOUmpIX3p4Y0tCeHNqUlBVdHpSYnA3RlNWTEtKWFE5QVBYOU1QMWo3azQifQ"
        )

        XCTAssertNil(resolutionResult.didDocument)
        XCTAssertEqual(
            resolutionResult.didResolutionMetadata.error, DIDResolutionResult.Error.methodNotSupported.rawValue)
    }

    func test_resolveNewlyCreatedDIDJWK() async throws {
        let keyManager = InMemoryKeyManager()
        let didJWK = try DIDJWK.create(keyManager: keyManager)

        let resolutionResult = await DIDJWK.resolve(didURI: didJWK.uri)
        XCTAssertNotNil(resolutionResult.didDocument)
        XCTAssertEqual(resolutionResult.didDocument?.id, didJWK.uri)
        XCTAssertEqual(resolutionResult.didDocument?.verificationMethod?.first?.id, "\(didJWK.uri)#0")
        XCTAssertEqual(resolutionResult.didDocument?.authentication?.first, .referenced("\(didJWK.uri)#0"))
        XCTAssertEqual(resolutionResult.didDocument?.assertionMethod?.first, .referenced("\(didJWK.uri)#0"))
        XCTAssertEqual(resolutionResult.didDocument?.capabilityDelegation?.first, .referenced("\(didJWK.uri)#0"))
        XCTAssertEqual(resolutionResult.didDocument?.capabilityInvocation?.first, .referenced("\(didJWK.uri)#0"))
        XCTAssertNil(resolutionResult.didResolutionMetadata.error)
    }

    func test_resolveWithKnownDIDURI() async {
        let didURI =
            "did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6c2hhLTI1NjpGZk1iek9qTW1RNGVmVDZrdndUSUpqZWxUcWpsMHhqRUlXUTJxb2JzUk1NIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6IkFOUmpIX3p4Y0tCeHNqUlBVdHpSYnA3RlNWTEtKWFE5QVBYOU1QMWo3azQifQ"
        let resolutionResult = await DIDJWK.resolve(didURI: didURI)

        XCTAssertNotNil(resolutionResult.didDocument)
        XCTAssertEqual(resolutionResult.didDocument?.id, didURI)
        XCTAssertEqual(resolutionResult.didDocument?.verificationMethod?.first?.id, "\(didURI)#0")
        XCTAssertEqual(resolutionResult.didDocument?.authentication?.first, .referenced("\(didURI)#0"))
        XCTAssertEqual(resolutionResult.didDocument?.assertionMethod?.first, .referenced("\(didURI)#0"))
        XCTAssertEqual(resolutionResult.didDocument?.capabilityDelegation?.first, .referenced("\(didURI)#0"))
        XCTAssertEqual(resolutionResult.didDocument?.capabilityInvocation?.first, .referenced("\(didURI)#0"))
        XCTAssertNil(resolutionResult.didResolutionMetadata.error)
    }

}
