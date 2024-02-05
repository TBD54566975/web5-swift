import CustomDump
import XCTest

@testable import Web5

final class BearerDIDTests: XCTestCase {

    func test_export() async throws {
        let didJWK = try DIDJWK.create(keyManager: InMemoryKeyManager())
        let portableDID = try await didJWK.export()

        XCTAssertNoDifference(portableDID.uri, didJWK.uri)
        XCTAssertNoDifference(portableDID.document, didJWK.document)
        XCTAssertNoDifference(portableDID.privateKeys.count, 1)
        XCTAssertNil(portableDID.metadata)
    }
}
