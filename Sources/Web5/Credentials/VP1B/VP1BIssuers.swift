import Foundation

public struct VP1BIssuers: Codable, CustomStringConvertible {
    public let trustedIssuers: [VP1BIssuer]

    public var description: String {
        if let jsonData = try? JSONSerialization.data(withJSONObject: expanded(), options: .prettyPrinted),
          let jsonString = String(data: jsonData, encoding: .utf8) {
           return jsonString
        } else {
           return "Error converting VP1BIssuers data to JSON string."
        }
    }

    public static func fetchIssuers() async throws -> VP1BIssuers {
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

    public func findIssuer(credential: VP1BCredential) throws -> VP1BIssuer {
        guard let issuer = trustedIssuers.first(where: { $0.id == credential.issuer }) else {
            throw Error.issuerNotFound
        }
        return issuer
    }

    func expanded() -> [String: Any] {
        return [
            "trustedIssuers": trustedIssuers.map { issuer in
                return issuer.expanded()
            }
        ]
    }
}


extension VP1BIssuers {
    public  enum Error: LocalizedError, Equatable {
        case invalidUrl
        case issuerNotFound
        case networkError(String)

        public var errorDescription: String? {
            switch self {
            case .invalidUrl:
                return "Invalid URL: The provided URL is invalid."
            case .issuerNotFound:
                return "Issuer Not Found: The provided issuer DID was not found in the trusted issuers list"
            case let .networkError(reason):
                return "Network Error: \(reason)"
            }
        }
    }
}
