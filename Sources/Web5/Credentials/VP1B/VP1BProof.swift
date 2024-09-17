import Foundation
import SwiftCBOR

public struct VP1BProof : Decodable, CustomStringConvertible {
    public let created: Date
    public let method: String
    public let value: String

    public var description: String {
        if let jsonData = try? JSONSerialization.data(withJSONObject: expanded(), options: .prettyPrinted),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            return jsonString
        } else {
            return "Error converting VP1BProof data to JSON string."
        }
    }

    public static func from(_ cborMap: CBOR) throws -> VP1BProof {
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
