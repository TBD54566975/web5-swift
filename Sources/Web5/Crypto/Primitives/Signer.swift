import Foundation

/// Protocol defining the behaviors required sign data
public protocol Signer: Verifier {

    /// Sign a payload using the provided private key
    /// - Parameters:
    ///   - payload: The data to be signed
    ///   - privateKey: Private key in JWK format
    /// - Returns: Data representing the signature
    static func sign<P>(payload: P, privateKey: Jwk) throws -> Data
    where P: DataProtocol
}
