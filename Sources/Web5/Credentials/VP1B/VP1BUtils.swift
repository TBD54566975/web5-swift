import Foundation
import CryptoKit
import SwiftCBOR
import Base58Swift
import VarInt

struct VP1BUtils {

    static func generatePayload(from vp1b: VP1B) -> [UInt8] {
        let proofCreated = vp1b.credential.proof.created
        let verificationMethod = vp1b.credential.proof.method
        let verifiableCredentialId = vp1b.credential.id
        let expirationDate = vp1b.credential.expiration
        let issuanceDate = vp1b.credential.issuance
        let issuer = vp1b.credential.issuer
        let overAge = vp1b.credential.subject.overAge
        let concealedIdToken = vp1b.credential.subject.concealedIdToken

        let proofQuads = """
        _:c14n0 <http://purl.org/dc/terms/created> "\(formatDate(proofCreated))"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
        _:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2020> .
        _:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
        _:c14n0 <https://w3id.org/security#verificationMethod> <\(verificationMethod)> .
        """

        let vcQuads = """
        <\(verifiableCredentialId)> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/age#OverAgeTokenCredential> .
        <\(verifiableCredentialId)> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
        <\(verifiableCredentialId)> <https://www.w3.org/2018/credentials#credentialSubject> _:c14n0 .
        <\(verifiableCredentialId)> <https://www.w3.org/2018/credentials#expirationDate> "\(formatDate(expirationDate))"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
        <\(verifiableCredentialId)> <https://www.w3.org/2018/credentials#issuanceDate> "\(formatDate(issuanceDate))"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
        <\(verifiableCredentialId)> <https://www.w3.org/2018/credentials#issuer> <\(issuer)> .
        _:c14n0 <https://w3id.org/age#overAge> "\(overAge)"^^<http://www.w3.org/2001/XMLSchema#positiveInteger> .
        _:c14n0 <https://w3id.org/cit#concealedIdToken> "\(concealedIdToken)"^^<https://w3id.org/security#multibase> .
        """

        let proofQuadsHash = sha256(proofQuads)
        let vcQuadsHash = sha256(vcQuads)

        return proofQuadsHash + vcQuadsHash
    }

    static func generateSignature(from vp1b: VP1B) throws -> Data {
        let proofValue = vp1b.credential.proof.value
        let slicedProofValue = String(proofValue.dropFirst())

        guard let decodedData = Base58.base58Decode(slicedProofValue) else {
            throw Error.signatureGenerationFailed
        }
        return Data(decodedData)
    }

    static func generatePublicKey(from vp1b: VP1B) throws -> Jwk {
        let verificationMethod = vp1b.credential.proof.method
        let components = verificationMethod.split(separator: "#")
        guard components.count > 1 else {
            throw Error.invalidCredential
        }

        let fingerprint = String(components[1])
        let slicedFingerprint = String(fingerprint.dropFirst())

        guard let idBytes = Base58.base58Decode(slicedFingerprint) else {
            throw Error.invalidPublicKey
        }

        let varInt = uVarInt(idBytes)
        let publicKeyBytes = Array(idBytes.dropFirst(varInt.bytesRead))

        guard publicKeyBytes.count == 32 else {
            throw Error.invalidPublicKey
        }

        return try Ed25519.publicKeyFromBytes(Data(publicKeyBytes))
    }

    static func sha256(_ input: String) -> [UInt8] {
        let data = Data(input.utf8)
        let hashed = SHA256.hash(data: data)
        return Array(hashed)
    }

    private static func formatDate(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    static func toUUID(_ data: CBOR) throws -> String {
        guard case let .unsignedInt(type) = data[0], type == 3,
              case let .byteString(bytes) = data[1] else {
            throw Error.invalidCredential
        }

        let uuidString = UUID.from(byteArray: bytes)!.uuidString
        return "urn:uuid:\(uuidString)"
    }

    static func toInstant(_ data: CBOR) throws -> Date {
        guard case let .unsignedInt(timestamp) = data else {
            throw Error.invalidCredential
        }
        return Date(timeIntervalSince1970: TimeInterval(timestamp))
    }

    static func toDID(_ data: CBOR) throws -> String {
        guard case let .array(array) = data, array.count >= 2,
              case let .unsignedInt(scheme) = array[0],
              case let .byteString(authorityBytes) = array[1] else {
            throw Error.invalidCredential
        }

        guard scheme == 1025 else {
            throw Error.invalidCredential
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

    static func encodeMultibasePublicKey(_ multicodecKeyBytes: [UInt8]) -> String {
        return "z" + Base58.base58Encode(multicodecKeyBytes)
    }

    static func toMultibase(_ data: CBOR) throws -> String {
        guard case let .byteString(bytes) = data else {
            throw Error.invalidCredential
        }
        let encoding = bytes[0]
        let content = Array(bytes.dropFirst())

        if encoding != 0x7a {
            throw Error.invalidCredential
        }

        return "z" + Base58.base58Encode(content)
    }

    static func toInt(_ data: CBOR) throws -> Int64 {
        guard case let .unsignedInt(value) = data else {
            throw Error.invalidCredential
        }
        return Int64(value)    }
}

extension UUID {
    static func from(byteArray: [UInt8]) -> UUID? {
        guard byteArray.count == 16 else {
            return nil
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

extension VP1BUtils {
    public enum Error: LocalizedError, Equatable {
            case invalidCredential
            case invalidPublicKey
            case signatureGenerationFailed

            public var errorDescription: String? {
                switch self {
                case .invalidCredential:
                    return "Invalid Credential: The credential data is missing or incorrect."
                case .invalidPublicKey:
                    return "Invalid Public Key: The public key extraction failed."
                case .signatureGenerationFailed:
                    return "Signature Generation Failed: Could not generate a valid signature."
                }
            }
        }
}
