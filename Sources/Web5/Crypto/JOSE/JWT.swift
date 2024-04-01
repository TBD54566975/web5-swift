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

        /// "misc" Miscellaneous claim is a map to store any additional claims
        ///
        let miscellaneous: [String: AnyCodable]

        // Default Initializer
        public init(
            issuer: String? = nil,
            subject: String? = nil,
            audience: String? = nil,
            expiration: Date? = nil,
            notBefore: Date? = nil,
            issuedAt: Date? = nil,
            jwtID: String? = nil,
            misc: [String: AnyCodable] = [:]
        ) {
            self.issuer = issuer
            self.subject = subject
            self.audience = audience
            self.expiration = expiration
            self.notBefore = notBefore
            self.issuedAt = issuedAt
            self.jwtID = jwtID
            self.miscellaneous = misc
        }

        enum CodingKeys: String, CodingKey {
            case issuer = "iss"
            case subject = "sub"
            case audience = "aud"
            case expiration = "exp"
            case notBefore = "nbf"
            case issuedAt = "iat"
            case jwtID = "jti"
            case miscellaneous = "misc"
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
        
        let jwtHeader: JWS.Header = try JSONDecoder().decode(
            JWS.Header.self,
            from: try base64urlEncodedJwtHeader.decodeBase64Url()
        )

        guard jwtHeader.type == "JWT" else {
            throw Error.verificationFailed("Expected JWT header to contain typ property set to JWT")
        }

        guard jwtHeader.keyID != nil else {
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

// MARK: - JWT Claims Encoding

extension JWT.Claims {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encodeIfPresent(issuer, forKey: .issuer)
        try container.encodeIfPresent(subject, forKey: .subject)
        try container.encodeIfPresent(audience, forKey: .audience)
        try container.encodeIfPresent(expiration, forKey: .expiration)
        try container.encodeIfPresent(notBefore, forKey: .notBefore)
        try container.encodeIfPresent(issuedAt, forKey: .issuedAt)
        try container.encodeIfPresent(jwtID, forKey: .jwtID)

        // Encode each key/value from the miscellaneous dictionary directly into the container
        for (key, value) in miscellaneous {
            let dynamicKey = DynamicCodingKey(stringValue: key)!
            try container.encode(value, forKey: dynamicKey)
        }
    }
}

// MARK: - JWT Claims Decoding

extension JWT.Claims {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        issuer = try container.decodeIfPresent(String.self, forKey: .issuer)
        subject = try container.decodeIfPresent(String.self, forKey: .subject)
        audience = try container.decodeIfPresent(String.self, forKey: .audience)
        
        // these are ISO8601 dates, do i need to do some additional decoding?
        expiration = try container.decodeIfPresent(Date.self, forKey: .expiration)
        notBefore = try container.decodeIfPresent(Date.self, forKey: .notBefore)
        issuedAt = try container.decodeIfPresent(Date.self, forKey: .issuedAt)
        
        jwtID = try container.decodeIfPresent(String.self, forKey: .jwtID)

        let allKeys = container.allKeys
        var misc = [String: AnyCodable]()

        // Filtering out known coding keys
        for key in allKeys {
            if !(CodingKeys(rawValue: key.stringValue) != nil) {
                let value = try container.decode(AnyCodable.self, forKey: key)
                misc[key.stringValue] = value
            }
        }

        miscellaneous = misc
    }
}

// MARK: - DynamicCodingKey

// DynamicCodingKey is used to dynamically encode keys not predefined in the CodingKeys enum.
struct DynamicCodingKey: CodingKey {
    var stringValue: String
    var intValue: Int?
    
    init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }
    
    init?(intValue: Int) {
        self.stringValue = "\(intValue)"
        self.intValue = intValue
    }
}
