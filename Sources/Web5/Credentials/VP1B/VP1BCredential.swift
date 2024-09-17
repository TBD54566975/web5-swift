import Foundation
import SwiftCBOR

public struct VP1BCredential : Decodable, CustomStringConvertible {
    public let id: String
    public let issuance: Date
    public let expiration: Date
    public let issuer: String
    public let subject: VP1BSubject
    public let proof: VP1BProof

    static let verifiableCredential = "VerifiableCredential"
    static let overAgeTokenCredential = "OverAgeTokenCredential"
    static let types: [String] = [verifiableCredential, overAgeTokenCredential]

    public var description: String {
        if let jsonData = try? JSONSerialization.data(withJSONObject: expanded(), options: .prettyPrinted),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            return jsonString
        } else {
            return "Error converting VP1BCredential data to JSON string."
        }
    }

    func expanded() -> [String: Any] {
        return [
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/age/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": id,
            "type": VP1BCredential.types,
            "issuer": issuer,
            "issuanceDate": ISO8601DateFormatter().string(from: issuance),
            "expirationDate": ISO8601DateFormatter().string(from: expiration),
            "credentialSubject": subject.expanded(),
            "proof": proof.expanded()
        ]
    }

    public static func from(_ cborMap: CBOR) throws -> VP1BCredential {
        return VP1BCredential(
            id: try VP1BUtils.toUUID(cborMap[CBOR.unsignedInt(112)]!),
            issuance: try VP1BUtils.toInstant(cborMap[CBOR.unsignedInt(164)]!),
            expiration: try VP1BUtils.toInstant(cborMap[CBOR.unsignedInt(162)]!),
            issuer: try VP1BUtils.toDID(cborMap[CBOR.unsignedInt(168)]!),
            subject: try VP1BSubject.from(cborMap[CBOR.unsignedInt(158)]!),
            proof: try VP1BProof.from(cborMap[CBOR.unsignedInt(114)]!)
        )
    }
}
