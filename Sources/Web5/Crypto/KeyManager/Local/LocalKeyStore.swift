import Foundation

/// Protocol for a store which can save keys locally on device
public protocol LocalKeyStore {

    /// Get a key from the store
    /// - Parameter keyAlias: Alias of the key to retrieve
    /// - Returns: Key in JWK format (if available)
    func getKey(keyAlias: String) throws -> Jwk?

    /// Set a key in the store
    /// - Parameters:
    ///   - key: Key to store in JWK format
    ///   - keyAlias: Alias to index the key within the store
    func setKey(_ privateKey: Jwk, keyAlias: String) throws
}
