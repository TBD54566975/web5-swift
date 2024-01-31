import Foundation

/// A KeyManager that generates and stores cryptographic keys locally on device
public class LocalKeyManager: KeyManager {
    /// Backing store to store generated keys
    let keyStore: LocalKeyStore

    /// Default initializer
    init(keyStore: LocalKeyStore) {
        self.keyStore = keyStore
    }

    /// Generate a private key and store it locally on device
    /// - Parameters
    ///   - algorithm: `CryptoAlgorithm` to use for key generation
    /// - Returns: Alias of the generated key
    public func generatePrivateKey(algorithm: CryptoAlgorithm) throws -> String {
        let privateKey = try Crypto.generatePrivateKey(algorithm: algorithm)
        let keyAlias = try getDeterministicAlias(key: privateKey)

        try keyStore.setKey(privateKey, keyAlias: keyAlias)

        return keyAlias
    }

    public func getPublicKey(keyAlias: String) throws -> Jwk {
        let privateKey = try getPrivateKey(keyAlias: keyAlias)
        let publicKey = try Crypto.computePublicKey(privateKey: privateKey)

        return publicKey
    }

    public func sign<D>(keyAlias: String, payload: D) throws -> Data where D: DataProtocol {
        let privateKey = try getPrivateKey(keyAlias: keyAlias)
        let signature = try Crypto.sign(payload: payload, privateKey: privateKey)

        return signature
    }

    public func getDeterministicAlias(key: Jwk) throws -> String {
        let alias: String

        if let keyIdentifier = key.keyIdentifier {
            alias = keyIdentifier
        } else {
            alias = try key.thumbprint()
        }

        return alias
    }

    // MARK: - Private

    private func getPrivateKey(keyAlias: String) throws -> Jwk {
        guard let privateKey = try keyStore.getKey(keyAlias: keyAlias) else {
            throw LocalKeyManager.Error.keyNotFound(keyAlias)
        }

        return privateKey
    }
}

// MARK: - KeyExporter

extension LocalKeyManager: KeyExporter {

    public func exportKey(keyAlias: String) throws -> Jwk {
        try getPrivateKey(keyAlias: keyAlias)
    }
}

// MARK: - KeyImporter

extension LocalKeyManager: KeyImporter {

    public func `import`(key: Jwk) throws -> String {
        let keyAlias = try getDeterministicAlias(key: key)
        try keyStore.setKey(key, keyAlias: keyAlias)

        return keyAlias
    }
}

// MARK: - Errors

extension LocalKeyManager {

    /// Errors thrown by `LocalKeyManager`
    public enum Error: LocalizedError {
        case keyNotFound(String)

        public var errorDescription: String? {
            switch self {
            case let .keyNotFound(keyAlias):
                return "Key not found for alias: \(keyAlias)"
            }
        }
    }
}
