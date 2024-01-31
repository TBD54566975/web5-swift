import Foundation

public enum OneOrMany<T: Codable & Equatable>: Codable, Equatable {
    case one(T)
    case many([T])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let singleValue = try? container.decode(T.self) {
            self = .one(singleValue)
        } else if let arrayValue = try? container.decode([T].self) {
            self = .many(arrayValue)
        } else {
            throw DecodingError.typeMismatch(
                OneOrMany.self,
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Expected either \(T.self) or [\(T.self)]"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .one(let singleValue):
            try container.encode(singleValue)
        case .many(let arrayValue):
            try container.encode(arrayValue)
        }
    }
}
