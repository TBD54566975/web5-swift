import CryptoKit
import Foundation

/// Cryptographic operations using the Edwards-curve Digital Signature Algorithm (EdDSA)
/// with the Ed25519 elliptic curve
public enum Ed25519: AsymmetricKeyGenerator, Signer {

    enum Error: Swift.Error {
        case invalidPrivateJwk
        case invalidPublicJwk
    }

    public static func generatePrivateKey() throws -> Jwk {
        return try Curve25519.Signing.PrivateKey().jwk()
    }

    public static func computePublicKey(privateKey: Jwk) throws -> Jwk {
        let privateKey = try Curve25519.Signing.PrivateKey(privateJwk: privateKey)
        return try privateKey.publicKey.jwk()
    }

    public static func privateKeyToBytes(_ privateKey: Jwk) throws -> Data {
        let privateKey = try Curve25519.Signing.PrivateKey(privateJwk: privateKey)
        return privateKey.rawRepresentation
    }

    public static func privateKeyFromBytes(_ bytes: Data) throws -> Jwk {
        return try Curve25519.Signing.PrivateKey(rawRepresentation: bytes).jwk()
    }

    public static func publicKeyToBytes(_ publicKey: Jwk) throws -> Data {
        let publicKey = try Curve25519.Signing.PublicKey(publicJwk: publicKey)
        return publicKey.rawRepresentation
    }

    public static func publicKeyFromBytes(_ bytes: Data) throws -> Jwk {
        return try Curve25519.Signing.PublicKey(rawRepresentation: bytes).jwk()
    }

    public static func sign<D>(payload: D, privateKey: Jwk) throws -> Data where D: DataProtocol {
        let privateKey = try Curve25519.Signing.PrivateKey(privateJwk: privateKey)
        return try privateKey.signature(for: payload)
    }

    public static func verify<P, S>(payload: P, signature: S, publicKey: Jwk) throws -> Bool
    where P: DataProtocol, S: DataProtocol {
        let publicKey = try Curve25519.Signing.PublicKey(publicJwk: publicKey)
        return publicKey.isValidSignature(signature, for: payload)
    }

    public static func isValidPrivateKey(_ privateKey: Jwk) -> Bool {
        let privateKey = try? Curve25519.Signing.PrivateKey(privateJwk: privateKey)
        return privateKey != nil
    }

    public static func isValidPublicKey(_ publicKey: Jwk) -> Bool {
        let publicKey = try? Curve25519.Signing.PublicKey(publicJwk: publicKey)
        return publicKey != nil
    }
}

// MARK: - Curve25519 Extensions

extension Curve25519.Signing.PrivateKey {

    init(privateJwk: Jwk) throws {
        guard
            privateJwk.keyType == .octetKeyPair,
            privateJwk.algorithm == .eddsa || privateJwk.curve == .ed25519,
            privateJwk.y == nil,
            let d = privateJwk.d
        else {
            throw Ed25519.Error.invalidPrivateJwk
        }

        try self.init(rawRepresentation: d.decodeBase64Url())
    }

    func jwk() throws -> Jwk {
        var jwk = try publicKey.jwk()
        jwk.d = rawRepresentation.base64UrlEncodedString()
        return jwk
    }

}

extension Curve25519.Signing.PublicKey {

    init(publicJwk: Jwk) throws {
        guard
            publicJwk.keyType == .octetKeyPair,
            publicJwk.algorithm == .eddsa || publicJwk.curve == .ed25519,
            publicJwk.y == nil,
            publicJwk.d == nil,
            let x = publicJwk.x
        else {
            throw Ed25519.Error.invalidPublicJwk
        }

        try self.init(rawRepresentation: x.decodeBase64Url())
    }

    func jwk() throws -> Jwk {
        var jwk = Jwk(
            keyType: .octetKeyPair,
            algorithm: .eddsa,
            curve: .ed25519,
            x: rawRepresentation.base64UrlEncodedString()
        )
        jwk.keyID = try jwk.thumbprint()

        return jwk
    }

}
