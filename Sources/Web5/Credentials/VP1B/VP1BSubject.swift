import Foundation
import SwiftCBOR

public struct VP1BSubject : Decodable, CustomStringConvertible {
    public let concealedIdToken: String
    public let overAge: Int64

    public var description: String {
        if let jsonData = try? JSONSerialization.data(withJSONObject: expanded(), options: .prettyPrinted),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            return jsonString
        } else {
            return "Error converting VP1BSubject data to JSON string."
        }
    }

    public static func from(_ cborMap: CBOR) throws -> VP1BSubject {
        return VP1BSubject(
            concealedIdToken: try VP1BUtils.toMultibase(cborMap[CBOR.unsignedInt(138)]!),
            overAge: try VP1BUtils.toInt(cborMap[CBOR.unsignedInt(148)]!)
        )
    }

    func expanded() -> [String: Any] {
        return [
            "overAge": overAge,
            "concealedIdToken": concealedIdToken
        ]
    }
}
