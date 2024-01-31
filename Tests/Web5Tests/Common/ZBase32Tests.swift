import XCTest

@testable import Web5

final class ZBase32Tests: XCTestCase {
    
    // TODO: Make these real web5 test vectors
    let vectors: [(encoded: String, decoded: Data)] = [
        (
            encoded: "pb1sa5dx",
            decoded: "hello".data(using: .utf8)!
        ),
        (
            encoded: "pb1sa5dxrb5s6huccooo",
            decoded: "hello world!".data(using: .utf8)!
        ),
        (
            encoded: "ktwgkedtqiwsg43ycj3g675qrbug66bypj4s4hdurbzzc3m1rb4go3jyptozw6jyctzsqmo",
            decoded: "The quick brown fox jumps over the lazy dog.".data(using: .utf8)!
        ),
    ]

    func test_encodeAndDecode() throws {
        for vector in vectors {
            let encoded = ZBase32.encode(vector.decoded)
            XCTAssertEqual(encoded, vector.encoded)

            let decoded = try ZBase32.decode(vector.encoded)
            XCTAssertEqual(decoded, vector.decoded)
        }
    }

}
