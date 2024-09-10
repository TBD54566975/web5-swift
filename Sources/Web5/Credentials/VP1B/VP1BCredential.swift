import Foundation
import SwiftCBOR

struct VP1BCredential {
    let id: String
    let issuance: Date
    let expiration: Date
    let issuer: String
    let subject: VP1BSubject
    let proof: VP1BProof

    static func from(_ cborMap: CBOR) throws -> VP1BCredential {
        return VP1BCredential(
            id: try VP1BUtils.toUUID(cborMap[CBOR.unsignedInt(112)]!),
            issuance: try VP1BUtils.toInstant(cborMap[CBOR.unsignedInt(164)]!),
            expiration: try VP1BUtils.toInstant(cborMap[CBOR.unsignedInt(162)]!),
            issuer: try VP1BUtils.toDID(cborMap[CBOR.unsignedInt(168)]!),
            subject: try VP1BSubject.from(cborMap[CBOR.unsignedInt(158)]!),
            proof: try VP1BProof.from(cborMap[CBOR.unsignedInt(114)]!)
        )
    }

    func expanded() -> [String: Any] {
        return [
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/age/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": id,
            "type": ["VerifiableCredential", "OverAgeTokenCredential"],
            "issuer": issuer,
            "issuanceDate": ISO8601DateFormatter().string(from: issuance),
            "expirationDate": ISO8601DateFormatter().string(from: expiration),
            "credentialSubject": subject.expanded(),
            "proof": proof.expanded()
        ]
    }
}
