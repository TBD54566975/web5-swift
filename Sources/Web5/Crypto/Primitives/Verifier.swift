import Foundation

/// Protocol defining the behaviors required to verify signatures
public protocol Verifier {

    /// Verify a payload
    /// - Parameters:
    ///   - payload: The data to be verified
    ///   - signature: The signature of the payload
    ///   - publicKey: Public key in JWK format
    /// - Returns: Boolean indicating if the signature is valid for the payload
    static func verify<P, S>(payload: P, signature: S, publicKey: Jwk) throws -> Bool
    where P: DataProtocol, S: DataProtocol
}
