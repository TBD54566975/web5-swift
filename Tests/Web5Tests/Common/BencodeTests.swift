import XCTest

@testable import Web5

final class BencodeTests: XCTestCase {

    // MARK: - Encode

    func test_encode_list() throws {
        let encoded = try Bencode.encode(["spam", "eggs"])
        XCTAssertEqual(encoded, "l4:spam4:eggse")
    }

    func test_encode_list_empty() throws {
        let encoded = try Bencode.encode([])
        XCTAssertEqual(encoded, "le")
    }

    func test_encode_string() throws {
        let encoded = try Bencode.encode("spam")
        XCTAssertEqual(encoded, "4:spam")
    }

    func test_encode_string_empty() throws {
        let encoded = try Bencode.encode("")
        XCTAssertEqual(encoded, "0:")
    }

    func test_encode_number() throws {
        let int: Int = 42
        let encoded = try Bencode.encode(int)
        XCTAssertEqual(encoded, "i42e")

        let long: Int64 = 1234567890123456789
        let encodedLong = try  Bencode.encode(long)
        XCTAssertEqual(encodedLong, "i1234567890123456789e")
    }

    func test_encode_number_zero() throws {
        let encodedZero = try Bencode.encode(0)
        XCTAssertEqual(encodedZero, "i0e")

        let encodedNegativeZero = try Bencode.encode(-0)
        XCTAssertEqual(encodedNegativeZero, "i0e")
    }

    func test_encode_dictionary() throws {
        let encoded = try Bencode.encode(["spam": "eggs", "cow": "moo"])

        // Dictionaries are always encoded with their keys in lexicographically sorted order
        XCTAssertEqual(encoded, "d3:cow3:moo4:spam4:eggse")
    }

    func test_encode_unsupportedType() throws {
        XCTAssertThrowsError(try Bencode.encode(10.00)) { error in
            guard let error = error as? Bencode.Error else {
                XCTFail("Expected Bencode.Error")
                return
            }
            XCTAssertEqual(error, Bencode.Error.unsupportedType)
        }
    }

    // MARK: - Encode Bytes

    func test_encodeBytes_empty() throws {
        let input = Data()
        let expected = "0:".data(using: .utf8)!
        let result = try Bencode.encodeAsBytes(input)

        XCTAssertEqual(result, expected)
    }

    func test_encodeBytes_single() throws {
        let input = Data([65])
        let expected = "1:A".data(using: .utf8)!
        let result = try Bencode.encodeAsBytes(input)

        XCTAssertEqual(result, expected)
    }

    func test_encodeBytes_multiple() throws {
        let input = Data([65, 66, 67])
        let expected = "3:ABC".data(using: .utf8)!
        let result = try Bencode.encodeAsBytes(input)

        XCTAssertEqual(result, expected)
    }

    func test_encodeBytes_specialCharacters() throws {
        let input = Data([35, 36, 37])
        let expected = "3:#$%".data(using: .utf8)!
        let result = try Bencode.encodeAsBytes(input)

        XCTAssertEqual(result, expected)
    }

    func test_encodeBytes_largeData() throws {
        let input = Data(repeating: 0, count: 1_000_000)
        let expected = "1000000:".data(using: .utf8)! + input
        let result = try Bencode.encodeAsBytes(input)

        XCTAssertEqual(result, expected)
    }

    // MARK: - Decode

    func test_decode_dictionary() throws {
        let input = "d9:publisher3:bob17:publisher-webpage15:www.example.com18:publisher.location4:homee"
        let expected = [
            "publisher": "bob",
            "publisher-webpage": "www.example.com",
            "publisher.location": "home"
        ]
        let (result, _) = try Bencode.decode(input)

        XCTAssertEqual(result, expected)
    }

    func test_decode_string() throws {
        let input = "3:seq"
        let expected = "seq"
        let (result, _) = try Bencode.decode(input)

        XCTAssertEqual(result, expected)
    }

    func test_decode_number() throws {
        let input = "i42e"
        let expected = 42
        let (result, _) = try Bencode.decode(input)

        XCTAssertEqual(result, expected)
    }

    func test_decode_list() throws {
        let input = "l4:spam4:eggse"
        let expected = ["spam", "eggs"]
        let (result, _) = try Bencode.decode(input)

        XCTAssertEqual(result, expected)
    }
}
