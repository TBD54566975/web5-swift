import Foundation

/// Protocol defining the behaviors required for a DID Method to construct DIDs
public protocol DIDMethodCreator: DIDMethod {

    /// Creates a new `BearerDID` using the target DID Method
    ///
    /// This function should generate a new `BearerDID` in accordance with the DID Method
    /// specification being implemented, using the provided `keyManager`.
    ///
    /// - Parameters:
    ///   - keyManager: `KeyManager` used to generate and store the keys associated to the DID
    /// - Returns: `BearerDID` which can be used to sign & verify data
    static func create(
        keyManager: KeyManager
    ) throws -> BearerDID

    /// Import a `PortableDID`, which represents the target DID Method, into a `BearerDID`
    ///
    /// - Parameters:
    ///   - keyManager: `KeyManager` used to generate and store the keys associated to the DID
    ///   - portableDID: `PortableDID` to import into a `BearerDID`
    /// - Returns: `BearerDID` which can be used to sign & verify data
    static func `import`(
        keyManager: KeyManager,
        portableDID: PortableDID
    ) throws -> BearerDID
}
