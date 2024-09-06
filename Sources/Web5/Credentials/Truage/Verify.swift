import Foundation
import SwiftCBOR
import Base58Swift

enum VerificationError: Error {
    case invalidContext
    case missingVerifiableCredential
    case multipleCredentials
    case invalidCredential
    case overAgeMismatch
    case verificationFailed
}

struct VerificationResult {
    let verified: Bool
    let credential: [String: Any]?
    let issuer: String?
    let overAge: Bool?
    let verificationDetails: [String: Any]?
}

// Verifies QR code text containing a `VP1-` header and a base32-encoded
func verifyQrCodeText(qrCodeText: String) throws -> VerificationResult {
    do {
        // Decode the QR code text and get the CBOR map
        let cborMap = try fromQrCodeText(expectedHeader: "VP1-", text: qrCodeText)
        
        print("Decoded CBOR Map: \(String(describing: cborMap))")

        // Extract and convert fields from CBOR map
        guard let vcMap = cborMap[CBOR.unsignedInt(124)] else {
            throw VerificationError.invalidCredential
        }
        
        let verifiableCredentialId = try convertToUuid(vcMap[CBOR.unsignedInt(112)]!)
        print("Verifiable Credential ID: \(verifiableCredentialId)")

        let issuanceDate = convertToRfc3339Datetime(vcMap[CBOR.unsignedInt(164)]!)
        print("Issuance Date: \(issuanceDate)")

        let expirationDate = convertToRfc3339Datetime(vcMap[CBOR.unsignedInt(162)]!)
        print("Expiration Date: \(expirationDate)")

        // TODO: figure out how to convert to did
//        let issuer = try convertToDid(vcMap[CBOR.unsignedInt(168)]!)
//        print("Issuer: \(issuer)")
        
        guard let subjectMap = vcMap[CBOR.unsignedInt(158)] else {
            throw VerificationError.invalidCredential
        }
        let concealedIdToken = try convertToMultibase(subjectMap[CBOR.unsignedInt(138)]!)
        print("Concealed ID Token: \(concealedIdToken)")

        let overAge = try convertToInt(subjectMap[CBOR.unsignedInt(148)]!)
        print("Over Age: \(overAge)")

        guard let proofMap = vcMap[CBOR.unsignedInt(114)] else {
            throw VerificationError.invalidCredential
        }
        let proofCreated = convertToRfc3339Datetime(proofMap[CBOR.unsignedInt(182)]!)
        print("Proof Created: \(proofCreated)")

        let proofValue = try convertToMultibase(proofMap[CBOR.unsignedInt(192)]!)
        print("Proof Value: \(proofValue)")

        // TODO: figure out how to convert to did
//        let verificationMethod = try convertToDid(proofMap[CBOR.unsignedInt(194)]!)
//        print("Verification Method: \(verificationMethod)")
        
        return VerificationResult(
            verified: true,
            credential: [
                "id": verifiableCredentialId,
//                "issuer": issuer,
                "issuanceDate": issuanceDate,
                "expirationDate": expirationDate
            ],
            issuer: nil,
//            issuer: issuer,
            overAge: overAge >= 21,
            verificationDetails: nil // TODO: Add actual details here
        )

    } catch {
        print("Verification failed with error: \(error)")
        return VerificationResult(
            verified: false,
            credential: nil,
            issuer: nil,
            overAge: nil,
            verificationDetails: nil
        )
    }
}

func convertToUuid(_ data: CBOR) throws -> String {
    guard case let .array(array) = data, array.count == 2,
          case let .unsignedInt(type) = array[0], type == 3,
          case let .byteString(bytes) = array[1] else {
        print("Error: malformed UUID encoding", data)
        throw VerificationError.invalidCredential
    }
    
    // Convert the byte array into a UUID and format it as a URN
    let uuidString = UUID.from(byteArray: bytes).uuidString
    return "urn:uuid:\(uuidString)"
}

func convertToRfc3339Datetime(_ data: CBOR) -> String {
    guard case let .unsignedInt(timestamp) = data else {
        return ""
    }
    let datetime = Date(timeIntervalSince1970: TimeInterval(timestamp))
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: datetime)
}

func convertToDid(_ data: CBOR) throws -> String {
    // TODO: implement this with web5?
    return ""
}

func convertToMultibase(_ data: CBOR) throws -> String {
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

func convertToInt(_ data: CBOR) throws -> Int64 {
    guard case let .unsignedInt(value) = data else {
        throw VerificationError.invalidCredential
    }
    return Int64(value)
}

extension UUID {
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
