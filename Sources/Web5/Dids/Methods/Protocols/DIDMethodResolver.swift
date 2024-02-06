import Foundation

/// Protocol defining the behaviors required to resolve a DID Method
public protocol DIDMethodResolver: DIDMethod {

    /// Resolve a DID URI into a `DIDResolutionResult`, containing the resolved DID Document
    ///
    /// - Parameters:
    ///   - didURI: The DID URI to resolve
    /// - Returns: `DIDResolutionResult` containing the resolved DID Document
    static func resolve(
        didURI: String
    ) async -> DIDResolutionResult
}
