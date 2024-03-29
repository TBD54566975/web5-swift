import CustomDump
import XCTest

@testable import Web5

final class Web5TestVectorsDidJwk: XCTestCase {

    func test_resolve() throws {
        let testVector = try TestVector<String, DIDResolutionResult>(
            fileName: "resolve",
            subdirectory: "test-vectors/did_jwk"
        )

        let resolver = DIDJWK.Resolver()

        testVector.run { vector in
            let expectation = XCTestExpectation(description: "async resolve")
            Task {
                let didURI = vector.input
                let result = await resolver.resolve(didURI: didURI)
                XCTAssertNoDifference(result, vector.output)
                expectation.fulfill()
            }

            wait(for: [expectation], timeout: 1)
        }
    }

}
