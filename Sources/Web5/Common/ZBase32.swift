import Foundation

/// ZBase32 is a variant of Base32 encoding designed to be human-readable and more robust for oral transmission.
///
/// See [reference](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) for more information.
public enum ZBase32 {
    private static let ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
    private static let BITS_PER_BYTE = 8
    private static let BITS_PER_BASE32_CHAR = 5

    /// Mask for extracting 5 bits, equivalent to '11111' in binary
    private static let MASK_BASE32 = 0x1F

    /// Mask for byte within an integer, equivalent to '11111111' in binary
    private static let MASK_BYTE = 0xFF

    /// Size of the decoder array based on ASCII range
    private static let DECODER_SIZE = 128

    private static let decoder: [Int] = {
        var decoder: [Int] = Array(repeating: -1, count: DECODER_SIZE)
        for (index, char) in ALPHABET.enumerated() {
            decoder[Int(char.asciiValue!)] = index
        }
        return decoder
    }()

    /// Encodes given data into a zbase32 encoded string
    public static func encode(_ data: Data) -> String {
        if data.isEmpty {
            return ""
        }

        var result = ""
        var buffer = 0
        var bufferLength = 0

        for b in data {
            buffer = (buffer << BITS_PER_BYTE) + (Int(b) & MASK_BYTE)
            bufferLength += BITS_PER_BYTE

            while bufferLength >= BITS_PER_BASE32_CHAR {
                let charIndex = (buffer >> (bufferLength - BITS_PER_BASE32_CHAR)) & MASK_BASE32
                result.append(ALPHABET[ALPHABET.index(ALPHABET.startIndex, offsetBy: charIndex)])
                bufferLength -= BITS_PER_BASE32_CHAR
            }
        }

        // Handle any remaining bits that may not make up a full byte
        if bufferLength > 0 {
            let charIndex = (buffer << (BITS_PER_BASE32_CHAR - bufferLength)) & MASK_BASE32
            result.append(ALPHABET[ALPHABET.index(ALPHABET.startIndex, offsetBy: charIndex)])
        }

        return result
    }

    /// Decodes a zbase32 encoded string into data
    public static func decode(_ data: String) throws -> Data {
        if data.isEmpty {
            return Data()
        }

        var result = Data()
        var buffer = 0
        var bufferLength = 0

        for c in data {
            guard let asciiValue = c.asciiValue else {
                throw Error.invalidCharacter(c)
            }

            let index = decoder[Int(asciiValue)]
            guard index != -1 else {
                throw Error.invalidCharacter(c)
            }

            buffer = (buffer << BITS_PER_BASE32_CHAR) + index
            bufferLength += BITS_PER_BASE32_CHAR

            while bufferLength >= BITS_PER_BYTE {
                let b = (buffer >> (bufferLength - BITS_PER_BYTE)) & MASK_BYTE
                result.append(UInt8(b))
                bufferLength -= BITS_PER_BYTE
            }
        }

        return result
    }
}

// MARK : - Errors

extension ZBase32 {
    public enum Error: LocalizedError {
        case invalidCharacter(Character)

        public var errorDescription: String? {
            switch self {
            case let .invalidCharacter(c):
                return "Invalid zbase32 character: \(c)"
            }
        }
    }
}
