import Foundation

public struct VP1BIssuer: Codable {
    let id: String
    let name: String
    let credentialTypes: [String]

    func verify() throws {
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
