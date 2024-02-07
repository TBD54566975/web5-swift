import Foundation

/// `did:ion` DID Method
public enum DIDIon {

    public static let methodName = "ion"

    /// Resolves a `did:ion` URI into a `DIDResolutionResult`
    /// - Parameters:
    ///   - didURI: The DID URI to resolve
    /// - Returns: `DIDResolutionResult` containing the resolved DID Document.
    public static func resolve(
        didURI: String
    ) async -> DIDResolutionResult {
        guard let did = try? DID(didURI: didURI) else {
            return DIDResolutionResult(error: .invalidDID)
        }

        guard did.methodName == Self.methodName else {
            return DIDResolutionResult(error: .methodNotSupported)
        }

        let identifiersEndpoint = "https://ion.tbddev.org/identifiers"
        guard let url = URL(string: "\(identifiersEndpoint)/\(did.uri)") else {
            return DIDResolutionResult(error: .notFound)
        }

        do {
            let response = try await URLSession.shared.data(from: url)
            let resolutionResult = try JSONDecoder().decode(DIDResolutionResult.self, from: response.0)
            return resolutionResult
        } catch {
            return DIDResolutionResult(error: .notFound)
        }
    }
}
