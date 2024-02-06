import Foundation
import secp256k1

extension ECDSA {

    /// Crypto operations using the Elliptic Curve Digital Signature Algorithm (ECDSA)
    /// with the secp256k1 elliptic curve and SHA-256
    public enum Es256k: AsymmetricKeyGenerator, Signer {

        public static func generatePrivateKey() throws -> Jwk {
            return try secp256k1.Signing.PrivateKey().jwk()
        }

        public static func computePublicKey(privateKey: Jwk) throws -> Jwk {
            let privateKey = try secp256k1.Signing.PrivateKey(privateJwk: privateKey)
            return try privateKey.publicKey.jwk()
        }

        public static func privateKeyToBytes(_ privateKey: Jwk) throws -> Data {
            let privateKey = try secp256k1.Signing.PrivateKey(privateJwk: privateKey)
            return privateKey.dataRepresentation
        }

        public static func privateKeyFromBytes(_ bytes: Data) throws -> Jwk {
            return try secp256k1.Signing.PrivateKey(dataRepresentation: bytes).jwk()
        }

        public static func publicKeyToBytes(_ publicKey: Jwk) throws -> Data {
            let publicKey = try secp256k1.Signing.PublicKey(publicJwk: publicKey)
            return publicKey.uncompressedBytes()
        }

        public static func publicKeyFromBytes(_ bytes: Data) throws -> Jwk {
            return try secp256k1.Signing.PublicKey(
                dataRepresentation: bytes,
                format: bytes.count == secp256k1.Signing.PublicKey.Constants.compressedKeySize
                    ? .compressed
                    : .uncompressed
            ).jwk()
        }

        public static func sign<D>(payload: D, privateKey: Jwk) throws -> Data where D: DataProtocol {
            let privateKey = try secp256k1.Signing.PrivateKey(privateJwk: privateKey)
            return try privateKey.signature(for: payload).compactRepresentation
        }

        public static func verify<P, S>(payload: P, signature: S, publicKey: Jwk) throws -> Bool
        where P: DataProtocol, S: DataProtocol {
            let publicKey = try secp256k1.Signing.PublicKey(publicJwk: publicKey)
            let ecdsaSignature = try secp256k1.Signing.ECDSASignature(compactRepresentation: signature)
            let normalizedSignature = try ecdsaSignature.normalized()

            return publicKey.isValidSignature(normalizedSignature, for: payload)
        }

        public static func isValidPrivateKey(_ privateKey: Jwk) -> Bool {
            let privateKey = try? secp256k1.Signing.PrivateKey(privateJwk: privateKey)
            return privateKey != nil
        }

        public static func isValidPublicKey(_ publicKey: Jwk) -> Bool {
            let publicKey = try? secp256k1.Signing.PublicKey(publicJwk: publicKey)
            return publicKey != nil
        }

        /// Errors thrown by `ECDSA.Es256k`
        enum Error: Swift.Error {
            case invalidPrivateJwk
            case invalidPublicJwk
        }
    }
}

// MARK: - secp256k1 Extensions

extension secp256k1.Signing.PrivateKey {

    init(privateJwk: Jwk) throws {
        guard
            privateJwk.keyType == .elliptic,
            privateJwk.algorithm == .es256k || privateJwk.curve == .secp256k1,
            let d = privateJwk.d
        else {
            throw ECDSA.Es256k.Error.invalidPrivateJwk
        }

        try self.init(dataRepresentation: d.decodeBase64Url())
    }

    func jwk() throws -> Jwk {
        var jwk = try publicKey.jwk()
        jwk.d = dataRepresentation.base64UrlEncodedString()
        return jwk
    }

}

extension secp256k1.Signing.PublicKey {

    fileprivate enum Constants {
        /// Uncompressed key leading byte that indicates both the X and Y coordinates are available directly within the key.
        static let uncompressedKeyID: UInt8 = 0x04

        /// Size of an uncompressed public key, in bytes.
        ///
        /// An uncompressed key is represented with a leading 0x04 bytes,
        /// followed by 32 bytes for the x-coordinate and 32 bytes for the y-coordinate.
        static let uncompressedKeySize: Int = 65

        /// Size of a compressed public key, in bytes.
        ///
        /// A compressed key is represented with a leading 0x02 or 0x03 byte,
        /// followed by 32 bytes for the x-coordinate.
        static let compressedKeySize: Int = 33
    }

    init(publicJwk: Jwk) throws {
        guard
            publicJwk.keyType == .elliptic,
            publicJwk.algorithm == .es256k || publicJwk.curve == .secp256k1,
            publicJwk.d == nil,
            let x = publicJwk.x,
            let y = publicJwk.y
        else {
            throw ECDSA.Es256k.Error.invalidPublicJwk
        }

        var data = Data()
        data.append(Constants.uncompressedKeyID)
        data.append(contentsOf: try x.decodeBase64Url())
        data.append(contentsOf: try y.decodeBase64Url())

        guard data.count == Constants.uncompressedKeySize else {
            throw ECDSA.Es256k.Error.invalidPublicJwk
        }

        try self.init(dataRepresentation: data, format: .uncompressed)
    }

    func jwk() throws -> Jwk {
        let (x, y) = curvePoints()

        var jwk = Jwk(
            keyType: .elliptic,
            algorithm: .es256k,
            curve: .secp256k1,
            x: x.base64UrlEncodedString(),
            y: y.base64UrlEncodedString()
        )

        jwk.keyIdentifier = try jwk.thumbprint()
        return jwk
    }

    /// Computes the elliptic curve points (x and y coordinates) for target `PublicKey`
    func curvePoints() -> (Data, Data) {
        let uncompresssedBytes = self.uncompressedBytes()
        let x = uncompresssedBytes[1...32]
        let y = uncompresssedBytes[33...64]

        return (x, y)
    }

    /// Compute the compressed data bytes of a secp256k1 public signing Key
    func compressedBytes() -> Data {
        return bytesInFormat(.compressed)
    }

    /// Compute the uncompressed bytes of a secp256k1 public signing key
    func uncompressedBytes() -> Data {
        return bytesInFormat(.uncompressed)
    }

    /// Compute the bytes of a secp256k1 public signing key in the given format
    private func bytesInFormat(_ targetFormat: secp256k1.Format) -> Data {
        var keyLength = targetFormat.length
        var key = rawRepresentation

        let context = secp256k1.Context.rawRepresentation
        var bytes = [UInt8](repeating: 0, count: keyLength)
        secp256k1_ec_pubkey_serialize(context, &bytes, &keyLength, &key, targetFormat.rawValue)
        return Data(bytes)
    }
}

extension secp256k1.Signing.ECDSASignature {

    /// Normalizes target ECDSASignature to low-s value.
    func normalized() throws -> secp256k1.Signing.ECDSASignature {
        let context = secp256k1.Context.rawRepresentation
        var signature = secp256k1_ecdsa_signature()
        dataRepresentation.copyToUnsafeMutableBytes(of: &signature.data)

        var normalized = secp256k1_ecdsa_signature()
        secp256k1_ecdsa_signature_normalize(
            context,
            &normalized,
            &signature
        )

        return try Self(dataRepresentation: normalized.dataValue)
    }
}
