import Foundation

/// [Specification Reference](https://datatracker.ietf.org/doc/html/rfc7515)]
public struct JWS {

    // Supported JWS algorithms
    public enum Algorithm: String, Codable {
        case eddsa
        case es256k
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
}

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
