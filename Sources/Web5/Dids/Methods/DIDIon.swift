import Foundation

/// `did:ion` DID Method
public enum DIDIon {}

// MARK: - Resolver

extension DIDIon {
    
    /// Resolver for the `did:ion` DID method
    public struct Resolver: DIDMethodResolver {

        /// Options that can be configured for resolving `did:ion` DIDs
        public struct ResolutionOptions {

            /// The URI of a server involved in executing DID method operations. In the context of
            /// DID creation, the endpoint is expected to be a Sidetree node.
            public let gatewayURI: String

            /// Public Memberwise Initializer
            public init(
                gatewayURI: String
            ) {
                self.gatewayURI = gatewayURI
            }

            /// Default ResolutionOptions
            public static let `default` = ResolutionOptions(
                gatewayURI: "https://ion.tbddev.org"
            )
        }

        /// Initialize a new `DIDIon.Resolver`
        /// - Parameters:
        ///   - options: The options to use for resolution process
        public init(
            options: ResolutionOptions = .default
        ) {
            self.options = options
        }

        /// The options to use for resolution process
        public let options: ResolutionOptions

        // MARK: DIDMethodResolver

        public let methodName = "ion"

        /// Resolves a `did:ion` URI into a `DIDResolutionResult`
        /// - Parameters:
        ///   - didURI: The DID URI to resolve
        /// - Returns: `DIDResolutionResult` containing the resolved DID Document.
        public func resolve(
            didURI: String
        ) async -> DIDResolutionResult {
            guard let did = try? DID(didURI: didURI) else {
                return DIDResolutionResult(error: .invalidDID)
            }

            guard did.methodName == methodName else {
                return DIDResolutionResult(error: .methodNotSupported)
            }

            guard let url = URL(string: "\(options.gatewayURI)/identifiers/\(did.uri)") else {
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
}
