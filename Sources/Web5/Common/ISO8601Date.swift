import Foundation

/// Wrapper used to easily encode a `Date` to and decode a `Date` from an ISO 8601 formatted date string.
@propertyWrapper
struct ISO8601Date: Codable {
    var wrappedValue: Date?

    init(wrappedValue: Date?) {
        self.wrappedValue = wrappedValue
    }

    init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        let stringValue = try value.decode(String.self)
        if let date = ISO8601DateFormatter().date(from: stringValue) {
            wrappedValue = date
        } else {
            throw DecodingError.typeMismatch(Date.self, DecodingError.Context(codingPath: [], debugDescription: "Failed to decode ISO Date. Invalid string format."))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()

        if let wrappedValue {
            let string = ISO8601DateFormatter().string(from: wrappedValue)
            try container.encode(string)
        }
    }
}
