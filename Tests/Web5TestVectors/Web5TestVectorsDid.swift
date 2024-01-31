import CustomDump
import XCTest

@testable import Web5

final class Web5TestVectorsDid: XCTestCase {

    func test_parse() throws {
        /// Output data format for `parse` test vectors
        struct Output: Codable {
            let method: String
            let id: String
            let params: [String: String]?
            let query: String?
            let fragment: String?
        }

        let testVector = try TestVector<String, Output>(
            fileName: "parse",
            subdirectory: "did"
        )

        testVector.run { vector in
            var did: DID?

            let parse = {
                did = try DID(didURI: vector.input)
            }

            if let errors = vector.errors {
                if errors {
                    return XCTAssertThrowsError(try parse())
                } else {
                    XCTAssertNoThrow(try parse())
                }
            } else {
                try parse()
            }

            guard let did else {
                return XCTFail("DID not parsed")
            }

            guard let output = vector.output else {
                return XCTFail("No output defined")
            }

            XCTAssertNoDifference(did.methodName, output.method)
            XCTAssertNoDifference(did.identifier, output.id)
            XCTAssertNoDifference(did.params, output.params)
            XCTAssertNoDifference(did.query, output.query)
            XCTAssertNoDifference(did.fragment, output.fragment)
        }
    }
}
