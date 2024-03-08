import Foundation

public enum OneOrMany<T: Codable & Equatable>: Codable, Equatable {
    case one(T)
    case many([T])

    public init(_ value: T) {
        self = .one(value)
    }

    public init?(_ value: T?) {
        if let value {
            self.init(value)
        } else {
            return nil
        }
    }

    public init?(_ values: [T]) {
        if values.count >= 2 {
            self = .many(values)
        } else if values.count == 1 {
            self = .one(values.first!)
        } else {
            return nil
        }
    }

    public init?(_ values: [T]?) {
        if let values {
            self.init(values)
        } else {
            return nil
        }
    }
    /*
     {
      thing: "thing",
     "grab": {
     "thing" : "thing"
     }
     */

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
