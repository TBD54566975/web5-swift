import CustomDump
import Mocker
import XCTest

@testable import Web5

final class Web5TestVectorsPresentationExchange: XCTestCase {

    func test_resolve() throws {
        struct Input: Codable {
            let presentationDefinition: PresentationDefinitionV2
            let credentialJwts: [String]
            let mockServer: [String: [String: String]]?

            func mocks() throws -> [Mock] {
                guard let mockServer = mockServer else { return [] }

                return try mockServer.map({ key, value in
                    return Mock(
                        url: URL(string: key)!,
                        contentType: .json,
                        statusCode: 200,
                        data: [
                            .get: try JSONEncoder().encode(value)
                        ]
                    )
                })
            }
        }
        
        struct Output: Codable {
            let selectedCredentials: [String]
        }

        let testVector = try TestVector<Input, Output>(
            fileName: "select_credentials",
            subdirectory: "test-vectors/presentation_exchange"
        )

        testVector.run { vector in
            let expectation = XCTestExpectation(description: "async resolve")
            Task {
                /// Register each of the mock network responses
                try vector.input.mocks().forEach { $0.register() }

                /// Select valid credentials from each of the inputs, make sure it matches output
                let result = try PresentationExchange.selectCredentials(vcJWTs: vector.input.credentialJwts, presentationDefinition: vector.input.presentationDefinition)
                XCTAssertEqual(result.sorted(), vector.output!.selectedCredentials.sorted())
                expectation.fulfill()
            }

            wait(for: [expectation], timeout: 10000)
        }
    }

}
