import Foundation

public struct VP1BIssuer: Codable, CustomStringConvertible {
    public let id: String
    public let name: String
    public let credentialTypes: [String]

    public var description: String {
        if let jsonData = try? JSONSerialization.data(withJSONObject: expanded(), options: .prettyPrinted),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            return jsonString
        } else {
            return "Error converting VP1BCredential data to JSON string."
        }
    }

    public func verify() throws {
        if !credentialTypes.contains(VP1BCredential.overAgeTokenCredential) {
            throw Error.invalidCredentialType
        }
    }

    func expanded() -> [String: Any] {
        return [
            "id": id,
            "name": name,
            "credentialTypes": credentialTypes,
        ]
    }
}

extension VP1BIssuer {
    public  enum Error: LocalizedError, Equatable {
        case invalidCredentialType

        public var errorDescription: String? {
            switch self {
            case .invalidCredentialType:
                return "Invalid Credential Type: OverAgeTokenCredential type missing"
            }
        }
    }
}
