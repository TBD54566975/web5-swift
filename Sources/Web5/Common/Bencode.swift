import Foundation

/// Bencode is a simple encoding scheme used by BitTorrent to encode arbitrary data.
///
/// See [spec](https://wiki.theory.org/BitTorrentSpecification#Bencoding) for more information
public enum Bencode {

    /// Errors that can be thrown by the Bencode encoding/decoding methods
    enum Error: Swift.Error {
        case unsupportedType
        case invalidData
    }

    // MARK: - Public Static Functions

    /// Encodes the given input into a Bencode formatted string
    /// - Parameters:
    ///   - input: The data to be encoded
    /// - Returns: The Bencode formatted string
    public static func encode(_ input: Any) throws -> String {
        if let inputString = input as? String {
            return "\(inputString.count):\(inputString)"
        } else if let inputInt = input as? Int {
            return "i\(inputInt)e"
        } else if let inputLong = input as? Int64 {
            return "i\(inputLong)e"
        } else if let inputList = input as? [Any] {
            let encodedList = try inputList.map { try encode($0) }.joined()
            return "l\(encodedList)e"
        } else if let inputMap = input as? [AnyHashable: Any] {
            // Bencode requires that dictionary keys are sorted lexicographically
            let sortedKeys = inputMap.keys.sorted { "\($0)" < "\($1)" }
            let encodedMap = try sortedKeys.map { key in
                guard let value = inputMap[key] else {
                    throw Error.unsupportedType
                }
                return try encode(key) + encode(value)
            }.joined()
            return "d\(encodedMap)e"
        } else {
            throw Error.unsupportedType
        }
    }

    /// Encodes a given input into a Bencode formatted byte array. Treats `Data` input as a string.
    /// - Parameters:
    ///   - input: The data to be encoded
    /// - Returns: The Bencode encoded Data
    public static func encodeAsBytes(_ input: Any) throws -> Data {
        if let inputBytes = input as? Data {
            guard let sizePrefix = "\(inputBytes.count):".data(using: .utf8) else {
                throw Error.invalidData
            }
            return sizePrefix + inputBytes
        } else {
            guard let encodedString = try? encode(input),
                  let stringData = encodedString.data(using: .utf8)
            else {
                throw Error.unsupportedType
            }
            return stringData
        }
    }


    /// Decodes a Bencode formatted string into its original data format
    /// - Parameter:
    ///   - input: The Benecode formatted string
    /// - Returns: A tuple containing the decoded data and the number of characters processed
    public static func decode(_ input: String) throws -> (AnyHashable, Int) {
        guard let currChar = input.first else {
            throw Error.invalidData
        }
        switch currChar {
        case "i", "l", "d":
            return try decodeType(input, type: currChar)
        default:
            return try decodeString(input)
        }
    }

    // MARK: - Private Static Functions

    private static func decodeType(_ s: String, type: Character) throws -> (AnyHashable, Int) {
        switch type {
        case "i":
            return try decodeInt(s)
        case "l":
            return try decodeList(s)
        case "d":
            return try decodeDict(s)
        default:
            return try decodeString(s)
        }
    }

    private static func decodeString(_ s: String) throws -> (String, Int) {
        guard let colonIndex = s.firstIndex(of: ":") else {
            throw Error.invalidData
        }
        let lengthPart = String(s[..<colonIndex])
        guard let length = Int(lengthPart), s.distance(from: colonIndex, to: s.endIndex) > length else {
            throw Error.invalidData
        }
        let startIndex = s.index(after: colonIndex)
        let endIndex = s.index(startIndex, offsetBy: length)
        return (String(s[startIndex..<endIndex]), length + lengthPart.count + 1)
    }

    private static func decodeInt(_ s: String) throws -> (Int, Int) {
        guard let eIndex = s.firstIndex(of: "e") else {
            throw Error.invalidData
        }
        let value = String(s[s.index(after: s.startIndex)..<eIndex])
        guard let intValue = Int(value) else {
            throw Error.invalidData
        }
        return (intValue, s.distance(from: s.startIndex, to: eIndex) + 1)
    }

    private static func decodeList(_ s: String) throws -> ([AnyHashable], Int) {
        var index = s.index(after: s.startIndex)
        var list = [AnyHashable]()
        while s[index] != "e" {
            let (decoded, length) = try decode(String(s[index...]))
            list.append(decoded)
            index = s.index(index, offsetBy: length)
        }
        return (list, s.distance(from: s.startIndex, to: index) + 1)
    }

    private static func decodeDict(_ s: String) throws -> ([AnyHashable: AnyHashable], Int) {
        var index = s.index(after: s.startIndex)
        var dict = [AnyHashable: AnyHashable]()
        while s[index] != "e" {
            let (key, keyLength) = try decode(String(s[index...]))
            index = s.index(index, offsetBy: keyLength)
            let (value, valueLength) = try decode(String(s[index...]))
            dict[key] = value
            index = s.index(index, offsetBy: valueLength)
        }
        return (dict, s.distance(from: s.startIndex, to: index) + 1)
    }
}
