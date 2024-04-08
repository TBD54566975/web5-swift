import XCTest
import AnyCodable
@testable import Web5

final class Web5TestVectorsPortableDid: XCTestCase {

    func test_parse() throws {
        
        struct Output: Codable {}
        struct OptionalPortableDid: Codable {
            typealias Metadata = [String: AnyCodable]
            let uri: String?
            let document: DIDDocument?
            let privateKeys: [Jwk]?
            let metadata: Metadata?
        }

        let testVector = try TestVector<OptionalPortableDid, Output>(
            fileName: "parse",
            subdirectory: "test-vectors/portable_did"
        )

        testVector.run { vector in

            guard let isError: Bool = vector.errors else {
                return XCTFail("Missing `errors` property")
            }

            let data = try JSONEncoder().encode(vector.input)
            
            if(isError) {
                XCTAssertThrowsError(try JSONDecoder().decode(PortableDID.self, from: data))
            } else {
                let dataModel = try JSONDecoder().decode(PortableDID.self, from: data)
                XCTAssertNotNil(dataModel);
            }
        }
    }
}