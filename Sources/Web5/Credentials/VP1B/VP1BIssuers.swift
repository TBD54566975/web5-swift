import Foundation

struct VP1BIssuers: Codable {
    let trustedIssuers: [Issuer]

    static func fetchIssuers() async throws -> VP1BIssuers {
        guard let trustedIssuersEndpoint = URL(string: "https://admin.sandbox.truage.dev/age/issuers") else {
            throw Error.invalidUrl
        }

        do {
            let (data, _) = try await URLSession.shared.data(from: trustedIssuersEndpoint)
            let trustedIssuers = try JSONDecoder().decode(VP1BIssuers.self, from: data)
            return trustedIssuers
        } catch {
            throw Error.networkError(error.localizedDescription)
        }
    }

    static func findIssuer(for credential: VP1BCredential, in issuers: VP1BIssuers) throws -> Issuer {
        guard let issuer = issuers.trustedIssuers.first(where: { $0.id == credential.issuer }) else {
            throw Error.issuerNotFound
        }
        return issuer
    }

    static func isValidCredentialType(issuer: Issuer) throws -> Bool {
        if !issuer.credentialTypes.contains(VP1BCredential.overAgeTokenCredential) {
            throw Error.invalidCredentialType
        }
        return true;
    }
}

struct Issuer: Codable {
    let id: String
    let name: String
    let credentialTypes: [String]
}

extension VP1BIssuers {
    public  enum Error: LocalizedError, Equatable {
        case invalidUrl
        case issuerNotFound
        case invalidCredentialType
        case networkError(String)

        public var errorDescription: String? {
            switch self {
            case .invalidUrl:
                return "Invalid URL: The provided URL is invalid."
            case .issuerNotFound:
                return "Issuer Not Found: The provided issuer DID was not found in the trusted issuers list"
            case .invalidCredentialType:
                return "Invalid Credential Type: OverAgeTokenCredential type missing"
            case let .networkError(reason):
                return "Network Error: \(reason)"
            }
        }
    }
}
