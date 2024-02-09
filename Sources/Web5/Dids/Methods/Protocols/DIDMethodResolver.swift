import Foundation

/// Protocol defining the behaviors common to all DID method resolvers
public protocol DIDMethodResolver {

    /// DID method name that the `DIDMethodResolver` is capable of resolving
    ///
    /// Example: In the DID URI `did:example:123`, the methodName is `example`
    var methodName: String { get }

    /// Resolves a DID URI into a `DIDResolutionResult`
    /// - Parameters:
    ///   - didURI: The DID URI to resolve
    /// - Returns: `DIDResolution.Result` containing the resolved DID Document
    func resolve(didURI: String) async -> DIDResolutionResult
}
