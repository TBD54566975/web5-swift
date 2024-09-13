import Foundation
import SwiftCBOR

struct VP1BProof : Decodable {
    let created: Date
    let method: String
    let value: String

    static func from(_ cborMap: CBOR) throws -> VP1BProof {
        return VP1BProof(
            created: try VP1BUtils.toInstant(cborMap[CBOR.unsignedInt(182)]!),
            method: try VP1BUtils.toDID(cborMap[CBOR.unsignedInt(194)]!),
            value: try VP1BUtils.toMultibase(cborMap[CBOR.unsignedInt(192)]!)
        )
    }

    func expanded() -> [String: Any] {
        return [
            "type": "Ed25519Signature2020",
            "created": ISO8601DateFormatter().string(from: created),
            "verificationMethod": method,
            "proofPurpose": "assertionMethod",
            "proofValue": value
        ]
    }
}
