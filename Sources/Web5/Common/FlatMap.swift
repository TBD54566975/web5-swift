import AnyCodable
import Foundation

/// Wrapper used to easily encode a `[String: AnyCodable]` to and decode a `[String: AnyCodable]` from a flat map.
@propertyWrapper
struct FlatMap: Codable {
    var wrappedValue: [String: AnyCodable]?

    init(wrappedValue: [String: AnyCodable]?) {
        self.wrappedValue = wrappedValue
    }

    init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        if let mapValue = try? value.decode([String: AnyCodable].self) {
            wrappedValue = mapValue
        } else {
            throw DecodingError.typeMismatch(Date.self, DecodingError.Context(codingPath: [], debugDescription: "TODO"))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()

        if let wrappedValue {
            try container.encode(wrappedValue)
        }
    }
}
