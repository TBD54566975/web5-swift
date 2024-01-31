import Foundation

/// A key management interface that provides functionality for generating, storing, and utilizing
/// private keys and their associated public keys. Implementations of this interface should handle
/// the secure generation and storage of keys, providing mechanisms for utilizing them in cryptographic
/// operations like signing.
///
/// Example implementations might provide key management through various Key Management Systems (KMS),
/// such as AWS KMS, Google Cloud KMS, Hardware Security Modules (HSM), or simple in-memory storage,
/// each adhering to the same consistent API for usage within applications.
public protocol KeyManager {

    /// Generates and securely stores a private key based on the provided keyType,
    /// returning a unique alias that can be utilized to reference the generated key for future operations.
    ///
    /// - Parameters:
    ///   - algorithm: The cryptographic algorithm to use for key generation.
    ///   - curve: The elliptic curve to use (relevant for EC algorithms).
    func generatePrivateKey(algorithm: CryptoAlgorithm) throws -> String

    /// Retrieves the public key associated with a previously stored private key, identified by the provided alias.
    ///
    /// - Parameters:
    ///   - keyAlias: The alias referencing the stored private key.
    /// - Returns: Public key in JSON Web Key (JWK) format.
    func getPublicKey(keyAlias: String) throws -> Jwk

    /// Signs the provided payload using the private key identified by the provided alias.
    ///
    /// - Parameters:
    ///   - keyAlias: The alias referencing the stored private key.
    ///   - payload: The data to be signed
    /// - Returns: Data representing the signature
    func sign<D>(keyAlias: String, payload: D) throws -> Data where D: DataProtocol

    /// Return the alias of `publicKey`, as was originally returned by `generatePrivateKey`.
    ///
    /// - Parameter key: A key in JSON Web Key (JWK) format
    /// - Returns: The alias belonging to `key`
    func getDeterministicAlias(key: Jwk) throws -> String
}
