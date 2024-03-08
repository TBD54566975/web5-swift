import Foundation
import AnyCodable

public struct JWT {

    /// Claims represents JWT (JSON Web Token) Claims
    ///
    /// See [RFC7519](https://tools.ietf.org/html/rfc7519#section-4) for more information
    public struct Claims: Codable {
        /// The "iss" (issuer) claim identifies the principal that issued the JWT.
        ///
        /// [Spec](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1)
        let issuer: String?

        /// The "sub" (subject) claim identifies the principal that is the subject of the JWT.
        ///
        /// [Spec](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2)
        let subject: String?

        /// The "aud" (audience) claim identifies the recipients that the JWT is intended for.
        ///
        /// [Spec](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3)
        let audience: String?

        /// The "exp" (expiration time) claim identifies the expiration time on
        /// or after which the JWT must not be accepted for processing.
        ///
        /// [Spec](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4)
        @ISO8601Date private(set) var expiration: Date?

        /// The "nbf" (not before) claim identifies the time before which the JWT
        /// must not be accepted for processing.
        ///
        /// [Spec](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5)
        @ISO8601Date private(set) var notBefore: Date?

        /// The "iat" (issued at) claim identifies the time at which the JWT was issued.
        ///
        /// [Spec](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6)
        @ISO8601Date private(set) var issuedAt: Date?

        /// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
        ///
        /// [Spec](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7)
        let jwtID: String?

        // Default Initializer
        public init(
            issuer: String? = nil,
            subject: String? = nil,
            audience: String? = nil,
            expiration: Date? = nil,
            notBefore: Date? = nil,
            issuedAt: Date? = nil,
            jwtID: String? = nil
        ) {
            self.issuer = issuer
            self.subject = subject
            self.audience = audience
            self.expiration = expiration
            self.notBefore = notBefore
            self.issuedAt = issuedAt
            self.jwtID = jwtID
        }

        enum CodingKeys: String, CodingKey {
            case issuer = "iss"
            case subject = "sub"
            case audience = "aud"
            case expiration = "exp"
            case notBefore = "nbf"
            case issuedAt = "iat"
            case jwtID = "jti"
        }
    }

    /// Signs the provied JWT claims with the provided BearerDID.
    /// - Parameters:
    ///  - did: The BearerDID to sign the JWT with
    ///  - claims: The claims to sign
    /// - Returns: The signed JWT
    public static func sign(did: BearerDID, claims: Claims) throws -> String {
        let payload = try JSONEncoder().encode(claims)

        return try JWS.sign(
            did: did,
            payload: payload,
            options: .init(
                detached: false,
                type: "JWT"
            )
        )
    }

    public struct ParsedJWT {
        let header: JWS.Header
        let payload: [String: AnyCodable]

        public init(
            header: JWS.Header,
            payload: [String: AnyCodable]
        ) {
            self.header = header
            self.payload = payload
        }
    }

    public static func parse(jwtString: String) throws -> ParsedJWT {
        let parts = jwtString.components(separatedBy: ".")

        guard parts.count == 3 else {
            throw Error.verificationFailed("Malformed JWT. Expected 3 parts. Got \(parts.count)")
        }
        
        let base64urlEncodedJwtHeader = String(parts[0])
        let base64urlEncodedJwtPayload = String(parts[1])
        let _ = String(parts[2])
        
        let jwtHeader: JWS.Header = try JSONDecoder().decode(
            JWS.Header.self,
            from: try base64urlEncodedJwtHeader.decodeBase64Url()
        )

        guard jwtHeader.type == "JWT" else {
            throw Error.verificationFailed("Expected JWT header to contain typ property set to JWT")
        }

        guard let _ = jwtHeader.keyID else {
            throw Error.verificationFailed("Expected JWT header to contain kid")
        }

        let jwtPayload = try JSONDecoder().decode(
            [String: AnyCodable].self,
            from: base64urlEncodedJwtPayload.decodeBase64Url()
        )

        return ParsedJWT(header: jwtHeader, payload: jwtPayload)
    }
}

// MARK: - Errors

extension JWT {
    public enum Error: LocalizedError {
        case verificationFailed(String)
        
        public var errorDescription: String? {
            switch self {
            case let .verificationFailed(reason):
                return "Verification Failed: \(reason)"
            }
        }
    }
}
