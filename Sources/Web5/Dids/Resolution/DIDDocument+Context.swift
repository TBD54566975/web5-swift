extension DIDDocument {

    /// [Specification Reference](https://www.w3.org/TR/did-core/#dfn-context)
    public enum Context: Codable, Equatable {
        case string(String)
        case list([ListElement])

        public enum ListElement: Codable, Equatable {
            case string(String)
            case orderedMap([String: String])

            public init(from decoder: Decoder) throws {
                let container = try decoder.singleValueContainer()
                if let str = try? container.decode(String.self) {
                    self = .string(str)
                } else if let dict = try? container.decode([String: String].self) {
                    self = .orderedMap(dict)
                } else {
                    throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid data")
                }
            }

            public func encode(to encoder: Encoder) throws {
                var container = encoder.singleValueContainer()
                switch self {
                case .string(let str):
                    try container.encode(str)
                case .orderedMap(let dict):
                    try container.encode(dict)
                }
            }
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let str = try? container.decode(String.self) {
                self = .string(str)
            } else if let list = try? container.decode([ListElement].self) {
                self = .list(list)
            } else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid data")
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .string(let str):
                try container.encode(str)
            case .list(let list):
                try container.encode(list)
            }
        }
    }
}
