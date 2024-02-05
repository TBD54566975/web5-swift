import Foundation

/// Protocol defining the behaviors required to resolve a DID Method
public protocol DIDMethodResolver: DIDMethod {

    /// Resolve a DID URI into a `DIDResolutionResult`, containing the resolved DID Document
    ///
    /// - Parameters:
    ///   - didURI: The DID URI to resolve
    ///   - options: The options to use when resolving the DID URI
    /// - Returns: `DIDResolutionResult` containing the resolved DID Document
    static func resolve(
        didURI: String,
        options: DIDMethodResolutionOptions?
    ) async -> DIDResolutionResult
}


/// Protocol defining the options that are available to configure when resolving a DID Method.
/// Each DID Method should define its own options type conforming to this protocol, if it has
/// method-specific customization options.
public protocol DIDMethodResolutionOptions {}
