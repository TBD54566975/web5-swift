import Foundation
import SwiftCBOR

struct VP1BSubject : Decodable {
    let concealedIdToken: String
    let overAge: Int64

    static func from(_ cborMap: CBOR) throws -> VP1BSubject {
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
