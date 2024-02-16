import Foundation

/// Cryptographic utility functions providing key generation, signature creation and verification,
/// and other crypto-related functionality.
public enum Crypto {

    /// Generate a private key for the specified cryptographic algorithm.
    /// - Parameter algorithm: Cryptographic algorithm to use for key generation.
    /// - Returns: JWK representation of the generated private key
    public static func generatePrivateKey(algorithm: CryptoAlgorithm) throws -> Jwk {
        guard let asymmetricKeyGenerator = algorithm.asymmetricKeyGenerator else {
            throw Crypto.Error.asymmetricKeyGenerationNotSupported(algorithm)
        }

        return try asymmetricKeyGenerator.generatePrivateKey()
    }

    /// Compute the public key for the specified private key.
    /// - Parameter privateKey: JWK representation of the private key to compute the public key for.
    /// - Returns: JWK representation of the computed public key.
    public static func computePublicKey(privateKey: Jwk) throws -> Jwk {
        guard let algorithm = CryptoAlgorithm.forPrivateKey(privateKey) else {
            throw Crypto.Error.unableToDetermineCryptoAlgorithm(privateKey)
        }

        guard let asymmetricKeyGenerator = algorithm.asymmetricKeyGenerator else {
            throw Crypto.Error.asymmetricKeyGenerationNotSupported(algorithm)
        }

        return try asymmetricKeyGenerator.computePublicKey(privateKey: privateKey)
    }

    /// Signs a payload using a private key.
    /// - Parameters:
    ///   - payload: The data to be signed
    ///   - privateKey: Private key in JWK format
    /// - Returns: Data representing the signature
    public static func sign<D>(payload: D, privateKey: Jwk) throws -> Data
    where D: DataProtocol {
        guard let algorithm = CryptoAlgorithm.forPrivateKey(privateKey) else {
            throw Crypto.Error.unableToDetermineCryptoAlgorithm(privateKey)
        }

        guard let signer = algorithm.signer else {
            throw Crypto.Error.signingNotSupported(algorithm)
        }

        return try signer.sign(payload: payload, privateKey: privateKey)
    }

    /// Verifies a signature against a signed payload using a public key
    /// - Parameters:
    ///   - payload: The data that was signed
    ///   - signature: The signature that will be verified
    ///   - publicKey: Public key in JWK format, to be used for verifying the signature
    ///   - algorithm: JWS algorithm used for signing/verification
    /// - Returns:  Boolean indicating if the publicKey and signature are valid for the given payload
    public static func verify<P, S>(
        payload: P,
        signature: S,
        publicKey: Jwk,
        jwsAlgorithm: JWS.Algorithm? = nil
    ) throws -> Bool
    where S: DataProtocol, P: DataProtocol {
        guard let cryptoAlgorithm = CryptoAlgorithm.forPublicKey(publicKey, jwsAlgorithm: jwsAlgorithm) else {
            throw Crypto.Error.unableToDetermineCryptoAlgorithm(publicKey)
        }

        guard let verifier = cryptoAlgorithm.verifier else {
            throw Crypto.Error.verifyingNotSupported(cryptoAlgorithm)
        }

        return try verifier.verify(payload: payload, signature: signature, publicKey: publicKey)
    }
}

// MARK: - Errors

extension Crypto {

    /// Errors thrown by `Crypto`
    public enum Error: LocalizedError {
        case unableToDetermineCryptoAlgorithm(Jwk)
        case asymmetricKeyGenerationNotSupported(CryptoAlgorithm)
        case signingNotSupported(CryptoAlgorithm)
        case verifyingNotSupported(CryptoAlgorithm)

        public var errorDescription: String? {
            switch self {
            case let .unableToDetermineCryptoAlgorithm(jwk):
                return "Unable to determine CryptoAlgorithm for JWK: \(jwk)"
            case let .asymmetricKeyGenerationNotSupported(algorithm):
                return "Asymmetric key generation not supported for algorithm: \(algorithm)"
            case let .signingNotSupported(algorithm):
                return "Signing not supported for algorithm: \(algorithm)"
            case let .verifyingNotSupported(algorithm):
                return "Verifying not supported for algorithm: \(algorithm)"
            }
        }
    }
}

// MARK: - Private CryptoAlgorithm static functions

extension CryptoAlgorithm {

    /// Compute the `CryptoAlgorithm` that can be used with a given private key
    /// - Parameters
    ///   - privateKey: Private key in JWK format
    /// - Returns: The `CryptoAlgorithm` that can be used with provided the `privateKey` (if available)
    fileprivate static func forPrivateKey(_ privateKey: Jwk) -> CryptoAlgorithm? {
        return CryptoAlgorithm
            .allCases
            .first { algorithm in
                if let asymmetricKeyGenerator = algorithm.asymmetricKeyGenerator {
                    return asymmetricKeyGenerator.isValidPrivateKey(privateKey)
                } else {
                    return false
                }
            }
            .self
    }

    /// Compute the `CryptoAlgorithm` that can be used with a given public key
    /// - Parameter publicKey: Public key in JWK format
    /// - Returns: The `CryptoAlgorithm` that can be used with provided the `publicKey` (if available)
    fileprivate static func forPublicKey(_ publicKey: Jwk, jwsAlgorithm: JWS.Algorithm? = nil) -> CryptoAlgorithm? {
        var algorithm: CryptoAlgorithm? = nil

        if let jwsAlgorithm {
            // If a JWS algorithm was provided, use that in conjunction
            // with the public key to determine the `CryptoAlgorithm`
            switch jwsAlgorithm {
            case .eddsa:
                // `.EdDSA` is common among multiple signature algorithms, so the
                // curve must be present on the JWK in order to fully determine the Signer
                if publicKey.curve == .ed25519 {
                    algorithm = .ed25519
                }
            case .es256k:
                algorithm = .secp256k1
            }
        } else {
            // If no JWS algorithm was provided, use the public key alone to determine the `CryptoAlgorithm`
            algorithm =
                CryptoAlgorithm
                .allCases
                .first { algorithm in
                    if let asymmetricKeyGenerator = algorithm.asymmetricKeyGenerator {
                        return asymmetricKeyGenerator.isValidPublicKey(publicKey)
                    } else {
                        return false
                    }
                }
                .self
        }

        return algorithm
    }
}

// MARK: - Private CryptoAlgorithm computed properties

extension CryptoAlgorithm {

    /// `Signer` associated with the `CryptoAlgorithm`
    fileprivate var signer: Signer.Type? {
        switch self {
        case .secp256k1:
            return Secp256k1.self
        case .ed25519:
            return Ed25519.self
        }
    }

    /// `Verifier` associated with the `CryptoAlgorithm`
    fileprivate var verifier: Verifier.Type? {
        return signer
    }

    /// `AsymmetricKeyGenerator` associated with the `CryptoAlgorithm`
    fileprivate var asymmetricKeyGenerator: AsymmetricKeyGenerator.Type? {
        switch self {
        case .secp256k1:
            return Secp256k1.self
        case .ed25519:
            return Ed25519.self
        }
    }
}
