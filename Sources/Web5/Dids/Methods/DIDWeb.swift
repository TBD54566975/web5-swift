import Foundation

/// `did:web` DID Method
enum DIDWeb: DIDMethod {

    public static let methodName = "web"
}

// MARK: - DIDMethodResolver

extension DIDWeb: DIDMethodResolver {

    /// Resolves a `did:web` URI into a `DIDResolutionResult`
    /// - Parameters:
    ///   - didURI: The DID URI to resolve
    ///   - options: The options to use when resolving the DID URI
    /// - Returns: `DIDResolution.Result` containing the resolved DID Document
    static func resolve(
        didURI: String,
        options: DIDMethodResolutionOptions? = nil
    ) async -> DIDResolutionResult {
        guard let did = try? DID(didURI: didURI),
            let url = getDIDDocumentUrl(did: did)
        else {
            return DIDResolutionResult(error: .invalidDID)
        }

        guard did.methodName == Self.methodName else {
            return DIDResolutionResult(error: .methodNotSupported)
        }

        do {
            let response = try await URLSession.shared.data(from: url)
            let didDocument = try JSONDecoder().decode(DIDDocument.self, from: response.0)
            return DIDResolutionResult(didDocument: didDocument)
        } catch {
            return DIDResolutionResult(error: .notFound)
        }
    }

    private static let wellKnownPath = "/.well-known"
    private static let didDocumentFilename = "/did.json"

    private static func getDIDDocumentUrl(did: DID) -> URL? {
        let domainNameWithPath = did.identifier.replacingOccurrences(of: ":", with: "/")
        guard let decodedDomain = domainNameWithPath.removingPercentEncoding,
            var url = URL(string: "https://\(decodedDomain)")
        else {
            return nil
        }

        if url.path.isEmpty {
            url.appendPathComponent(wellKnownPath)
        }

        url.appendPathComponent(didDocumentFilename)
        return url
    }

}
