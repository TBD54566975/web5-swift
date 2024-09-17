import Foundation
import SwiftCBOR

public struct VP1BSubject : Decodable {
    public let concealedIdToken: String
    public let overAge: Int64

    public static func from(_ cborMap: CBOR) throws -> VP1BSubject {
        return VP1BSubject(
            concealedIdToken: try VP1BUtils.toMultibase(cborMap[CBOR.unsignedInt(138)]!),
            overAge: try VP1BUtils.toInt(cborMap[CBOR.unsignedInt(148)]!)
        )
    }

    public func expanded() -> [String: Any] {
        return [
            "overAge": overAge,
            "concealedIdToken": concealedIdToken
        ]
    }
}
