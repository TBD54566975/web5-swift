import Foundation

public struct VP1BIssuer: Codable {
    public let id: String
    public let name: String
    public let credentialTypes: [String]

    public func verify() throws {
        if !credentialTypes.contains(VP1BCredential.overAgeTokenCredential) {
            throw Error.invalidCredentialType
        }
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
