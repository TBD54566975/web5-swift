import Foundation

/// Protocol defining the behaviors common to all DID method resolvers
public protocol DIDMethodResolver {

    /// Resolves a DID URI into a `DIDResolutionResult`
    /// - Parameters:
    ///   - didURI: The DID URI to resolve
    /// - Returns: `DIDResolution.Result` containing the resolved DID Document
    func resolve(didURI: String) async -> DIDResolutionResult

}
