import Foundation

/// [Specification Reference](https://datatracker.ietf.org/doc/html/rfc7515)]
public struct JWS {

    // Supported JWS algorithms
    public enum Algorithm: String, Codable {
        case eddsa = "EdDSA"
        case es256k = "ES256K"
    }

    /// JWS JOSE Header
    ///
    /// [Specification Reference](https://datatracker.ietf.org/doc/html/rfc7515#section-4)
    public struct Header: Codable {

        /// The "alg" (algorithm) Header Parameter identifies the cryptographic algorithm used to secure the JWS.
        public internal(set) var algorithm: Algorithm

        /// The "jku" (JWK Set URL) Header Parameter is a URI [[RFC3986](https://datatracker.ietf.org/doc/html/rfc3986)]
        /// that refers to a resource for a set of JSON-encoded public keys, one of which corresponds to the key used
        /// to digitally sign the JWS.
        public internal(set) var jwkSetURL: String?

        /// The "jwk" (JSON Web Key) Header Parameter is the public key that corresponds to the key used to digitally
        /// sign the JWS.
        public internal(set) var jwk: Jwk?

        /// The "kid" (key ID) Header Parameter is a hint indicating which key was used to secure the JWS.
        public internal(set) var keyID: String?

        /// The "x5u" (X.509 URL) Header Parameter is a URI [[RFC3986](https://datatracker.ietf.org/doc/html/rfc3986)]
        /// that refers to a resource for the X.509 public key certificate or certificate chain
        /// [RFC5280](https://datatracker.ietf.org/doc/html/rfc5280) corresponding to the key used to digitally sign
        /// the JWS.
        public internal(set) var x509URL: String?

        /// The "x5c" (X.509 certificate chain) Header Parameter contains the X.509 public key certificate or
        /// certificate chain [[RFC5280](https://datatracker.ietf.org/doc/html/rfc5280)] corresponding to the key used
        /// to digitally sign the JWS.
        public internal(set) var x509CertificateChain: String?

        /// The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a base64url-encoded SHA-1 thumbprint
        /// (a.k.a. digest) of the DER encoding of the X.509 certificate
        /// [[RFC5280](https://datatracker.ietf.org/doc/html/rfc5280)] corresponding to the key used to digitally sign
        /// the JWS.
        public internal(set) var x509CertificateSHA1Thumbprint: String?

        /// The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header Parameter is a base64url-encoded SHA-256
        /// thumbprint (a.k.a. digest) of the DER encoding of the X.509 certificate
        /// [[RFC5280](https://datatracker.ietf.org/doc/html/rfc5280)] corresponding to the key used to digitally sign
        /// the JWS.
        public internal(set) var x509CertificateSHA256Thumbprint: String?

        /// The "typ" (type) Header Parameter is used by JWS applications to declare the media type
        /// [[IANA.MediaTypes](https://datatracker.ietf.org/doc/html/rfc7515#ref-IANA.MediaTypes)] of this complete JWS.
        public internal(set) var type: String?

        /// The "cty" (content type) Header Parameter is used by JWS applications to declare the media type
        /// [[IANA.MediaTypes](https://datatracker.ietf.org/doc/html/rfc7515#ref-IANA.MediaTypes)] of the secured
        /// content (the payload).
        public internal(set) var contentType: String?

        /// The "crit" (critical) Header Parameter indicates that extensions to this specification
        /// and/or [[JWA](https://datatracker.ietf.org/doc/html/rfc7515#ref-JWA)] are being used that
        /// MUST be understood and processed.
        public internal(set) var critical: [String]?

        public init(
            algorithm: JWS.Algorithm,
            jwkSetURL: String? = nil,
            jwk: Jwk? = nil,
            keyID: String? = nil,
            x509URL: String? = nil,
            x509CertificateChain: String? = nil,
            x509CertificateSHA1Thumbprint: String? = nil,
            x509CertificateSHA256Thumbprint: String? = nil,
            type: String? = nil,
            contentType: String? = nil,
            critical: [String]? = nil
        ) {
            self.algorithm = algorithm
            self.jwkSetURL = jwkSetURL
            self.jwk = jwk
            self.keyID = keyID
            self.x509URL = x509URL
            self.x509CertificateChain = x509CertificateChain
            self.x509CertificateSHA1Thumbprint = x509CertificateSHA1Thumbprint
            self.x509CertificateSHA256Thumbprint = x509CertificateSHA256Thumbprint
            self.type = type
            self.contentType = contentType
            self.critical = critical
        }

        enum CodingKeys: String, CodingKey {
            case algorithm = "alg"
            case jwkSetURL = "jku"
            case jwk
            case keyID = "kid"
            case x509URL = "x5u"
            case x509CertificateChain = "x5c"
            case x509CertificateSHA1Thumbprint = "x5t"
            case x509CertificateSHA256Thumbprint = "x5t#S256"
            case type = "typ"
            case contentType = "cty"
            case critical = "crit"
        }
    }

    /// Options that can be used to configure the Sign operation of a JWS
    public struct SignOptions {
        /// Boolean determining if the payload is detached or not in the resulting JWS signature
        public let detached: Bool

        /// Optional `VerificationMethod` ID to use for signing. If not provided, the first
        /// verificationMethod in the `BearerDID`'s document will be used.
        public let verificationMethodID: String?

        // Optional type of verification method to use for signing. If not provided, the first
        public let type: String?

        public init(
            detached: Bool = false,
            verificationMethodID: String? = nil,
            type: String? = nil
        ) {
            self.detached = detached
            self.verificationMethodID = verificationMethodID
            self.type = type
        }
    }

    /// Signs the provided payload with a key associated with the provided `BearerDID`.
    /// - Parameters:
    ///   - did: `BearerDID` to use for signing
    ///   - payload: Data to be signed
    ///   - options: Options to configure the signing operation
    /// - Returns: compactJWS representation of the signed payload
    public static func sign<D>(
        did: BearerDID,
        payload: D,
        options: SignOptions
    ) throws -> String
    where D: DataProtocol {
        let signer = try did.getSigner(verificationMethodID: options.verificationMethodID)

        guard let publicKey = signer.verificationMethod.publicKeyJwk else {
            throw Error.signError("Public key not found")
        }

        guard let algorithm = publicKey.algorithm else {
            throw Error.signError("Public key algorithm not found")
        }

        let header = Header(
            algorithm: algorithm.jwsAlgorithm,
            keyID: signer.verificationMethod.id,
            type: options.type
        )
        
        let base64UrlEncodedHeader = try JSONEncoder().encode(header).base64UrlEncodedString()
        let base64UrlEncodedPayload = payload.base64UrlEncodedString()
        let toSign = "\(base64UrlEncodedHeader).\(base64UrlEncodedPayload)"
        let base64UrlEncodedSignature = try signer.sign(payload: Data(toSign.utf8)).base64UrlEncodedString()

        let compactJWS: String
        if options.detached {
            compactJWS = "\(base64UrlEncodedHeader)..\(base64UrlEncodedSignature)"
        } else {
            compactJWS = "\(base64UrlEncodedHeader).\(base64UrlEncodedPayload).\(base64UrlEncodedSignature)"
        }

        return compactJWS
    }

    /// Verifies the integrity of a compactJWS representation of a signed payload.
    /// - Parameters:
    ///   - compactJWS: compactJWS representation to verify
    ///   - detachedPayload: Optional detached payload to verify. If not provided, the payload will be assumed to be
    ///   attached within the compactJWS.
    ///   - expectedSigningDIDURI: Optional DID URI of the expected signer of the compactJWS. If not provided,
    ///   the DID URI will be extracted from the compactJWS, and will be assumed to be the correct signer.
    /// - Returns: Boolean indicating whether the provided compactJWS is valid
    public static func verify(
        compactJWS: String?,
        detachedPayload: (any DataProtocol)? = nil,
        expectedSigningDIDURI: String? = nil
    ) async throws -> Bool {
        guard let compactJWS else {
            throw Error.verifyError("compactJWS not provided")
        }

        let parts = compactJWS.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw Error.verifyError("Malformed JWS - Expected 3 parts, got \(parts.count)")
        }

        let base64UrlEncodedPayload: String
        if let detachedPayload {
            guard parts[1].count == 0 else {
                // Caller provided a detached payload to verify, but the compactJWS has a payload in it.
                // Throw an error, as this is likely a mistake by the caller.
                throw Error.verifyError("Expected detached payload")
            }
            base64UrlEncodedPayload = detachedPayload.base64UrlEncodedString()
        } else {
            base64UrlEncodedPayload = String(parts[1])
        }

        let base64UrlEncodedHeader = String(parts[0])
        let header = try JSONDecoder().decode(
            JWS.Header.self,
            from: try base64UrlEncodedHeader.decodeBase64Url()
        )

        guard let verificationMethodID = header.keyID else {
            throw Error.verifyError("Malformed JWS Header - `kid` is required")
        }
        
        let verificationMethodIDParts = verificationMethodID.split(separator: "#")
        guard verificationMethodIDParts.count == 2 else {
            throw Error.verifyError("Malformed JWS Header - `kid` must be a DID URI with a fragment")
        }

        let signingDIDURI = String(verificationMethodIDParts[0])
        if let expectedSigningDIDURI {
            guard signingDIDURI == expectedSigningDIDURI else {
                // The compactJWS was signed by someone other than the provided `expectedSigningDIDURI`.
                // This means that the signature is not valid for what the caller requested.
                return false
            }
        }

        let resolutionResult = await DIDResolver.resolve(didURI: signingDIDURI)

        if let error = resolutionResult.didResolutionMetadata.error {
            throw Error.verifyError("Failed to resolve \(signingDIDURI) - \(error)")
        }

        guard let verificationMethod = resolutionResult.didDocument?.verificationMethod?.first(
            where: { vm in vm.id == verificationMethodID }
        )
        else {
            throw Error.verifyError("No VerificationMethod not found that matches \(verificationMethodID)")
        }

        guard let publicKey = verificationMethod.publicKeyJwk else {
            throw Error.verifyError("VerificationMethod has no `publicKeyJwk`")
        }

        let base64UrlEncodedSignature = String(parts[2])
        let toVerify = "\(base64UrlEncodedHeader).\(base64UrlEncodedPayload)"

        return try Crypto.verify(
            payload: Data(toVerify.utf8),
            signature: try base64UrlEncodedSignature.decodeBase64Url(),
            publicKey: publicKey,
            jwsAlgorithm: header.algorithm
        )
    }
}

// MARK: - Errors

extension JWS {
    public enum Error: LocalizedError {
        case signError(String)
        case verifyError(String)

        public var errorDescription: String? {
            switch self {
            case let .signError(reason):
                return "Signing Error: \(reason)"
            case let .verifyError(reason):
                return "Verify Error: \(reason)"
            }
        }
    }
}

// MARK: - Extensions

extension Jwk.Algorithm {

    /// Converts a JWK algorithm to a JWS algorithm.
    public var jwsAlgorithm: JWS.Algorithm {
        switch self {
        case .eddsa:
            return .eddsa
        case .es256k:
            return .es256k
        }
    }
}
