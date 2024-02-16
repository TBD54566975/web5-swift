import Foundation

/// Cryptographic algorithms supported by the Web5
public enum CryptoAlgorithm: CaseIterable {

    /// EdDSA using the Ed25519 curve
    case ed25519
    /// ECDSA using the secp256k1 curve and SHA-256
    case secp256k1
}
