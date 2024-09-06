import Foundation
import SwiftCBOR
import Base58Swift

class CBORUtils {
    
    // Converts CBOR data to a UUID formatted as a URN
    static func convertToUuid(_ data: CBOR) throws -> String {
        guard case let .array(array) = data, array.count == 2,
              case let .unsignedInt(type) = array[0], type == 3,
              case let .byteString(bytes) = array[1] else {
            print("Error: malformed UUID encoding", data)
            throw VerificationError.invalidCredential
        }
        
        let uuidString = UUID.from(byteArray: bytes).uuidString
        return "urn:uuid:\(uuidString)"
    }
    
    // Converts a CBOR timestamp to an RFC3339 formatted datetime string
    static func convertToRfc3339Datetime(_ data: CBOR) -> String {
        guard case let .unsignedInt(timestamp) = data else {
            return ""
        }
        let datetime = Date(timeIntervalSince1970: TimeInterval(timestamp))
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: datetime)
    }
    
    // Encodes a public key to a multibase Base58 string
    static func encodeMultibasePublicKey(_ multicodecKeyBytes: [UInt8]) -> String {
        return "z" + Base58.base58Encode(multicodecKeyBytes)
    }
    
    // Converts CBOR data to a DID string
    static func convertToDid(_ data: CBOR) throws -> String {
        guard case let .array(array) = data, array.count >= 2,
              case let .unsignedInt(scheme) = array[0],
              case let .byteString(authorityBytes) = array[1] else {
            throw VerificationError.invalidCredential
        }

        guard scheme == 1025 else {
            throw VerificationError.invalidCredential
        }

        let authority = encodeMultibasePublicKey(authorityBytes)

        let did: String
        if array.count == 3, case let .byteString(fragmentBytes) = array[2] {
            let fragment = encodeMultibasePublicKey(fragmentBytes)
            did = "did:key:\(authority)#\(fragment)"
        } else {
            did = "did:key:\(authority)"
        }

        return did
    }
    
    // Converts CBOR byte string data to a multibase string
    static func convertToMultibase(_ data: CBOR) throws -> String {
        guard case let .byteString(bytes) = data else {
            throw VerificationError.invalidCredential
        }
        let encoding = bytes[0]
        let content = Array(bytes.dropFirst())
        
        if encoding != 0x7a {
            throw VerificationError.invalidCredential
        }
        
        return "z" + Base58.base58Encode(content)
    }
    
    // Converts CBOR data to an Int64
    static func convertToInt(_ data: CBOR) throws -> Int64 {
        guard case let .unsignedInt(value) = data else {
            throw VerificationError.invalidCredential
        }
        return Int64(value)
    }
}

extension UUID {
    // Creates a UUID from a 16-byte array
    static func from(byteArray: [UInt8]) -> UUID {
        guard byteArray.count == 16 else {
            fatalError("UUIDs must be exactly 16 bytes")
        }
        let uuid = uuid_t(
            byteArray[0], byteArray[1], byteArray[2], byteArray[3],
            byteArray[4], byteArray[5], byteArray[6], byteArray[7],
            byteArray[8], byteArray[9], byteArray[10], byteArray[11],
            byteArray[12], byteArray[13], byteArray[14], byteArray[15]
        )
        return UUID(uuid: uuid)
    }
}
