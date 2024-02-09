import Foundation

/// `did:web` DID Method
enum DIDWeb: DIDMethod {
    
    public static let methodName = "web"

}

// MARK: - Resolver

extension DIDWeb {

    /// Resolver fo the `did:web` DID method
    public struct Resolver: DIDMethodResolver {

        // MARK: Properties

        public let methodName = DIDWeb.methodName

        // MARK: Lifecycle

        /// Initialize a new resolver for the `did:web` method
        public init() {}

        // MARK: Public Functions

        /// Resolves a `did:web` URI into a `DIDResolutionResult`
        /// - Parameters:
        ///   - didURI: The DID URI to resolve
        /// - Returns: `DIDResolution.Result` containing the resolved DID Document
        public func resolve(
            didURI: String
        ) async -> DIDResolutionResult {
            guard let did = try? DID(didURI: didURI),
                  let url = getDIDDocumentUrl(did: did)
            else {
                return DIDResolutionResult(error: .invalidDID)
            }

            guard did.methodName == methodName else {
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

        // MARK: Private Functions

        private func getDIDDocumentUrl(
            did: DID
        ) -> URL? {
            let domainNameWithPath = did.identifier.replacingOccurrences(of: ":", with: "/")
            guard let decodedDomain = domainNameWithPath.removingPercentEncoding,
                  var url = URL(string: "https://\(decodedDomain)")
            else {
                return nil
            }

            if url.path.isEmpty {
                url.appendPathComponent("/.well-known")
            }

            url.appendPathComponent("/did.json")
            return url
        }
    }
}
