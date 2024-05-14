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
        let expiration: Int?

        /// The "nbf" (not before) claim identifies the time before which the JWT
        /// must not be accepted for processing.
        ///
        /// [Spec](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5)
        let notBefore: Int?

        /// The "iat" (issued at) claim identifies the time at which the JWT was issued.
        ///
        /// [Spec](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6)
        let issuedAt: Int?

        /// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
        ///
        /// [Spec](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7)
        let jwtID: String?

        /// "misc" Miscellaneous claim is a map to store any additional claims
        ///
        var miscellaneous: [String: AnyCodable]?

        // Default Initializer
        public init(
            issuer: String? = nil,
            subject: String? = nil,
            audience: String? = nil,
            expiration: Date? = nil,
            notBefore: Date? = nil,
            issuedAt: Date? = nil,
            jwtID: String? = nil,
            misc: [String: AnyCodable]? = nil
        ) {
            self.issuer = issuer
            self.subject = subject
            self.audience = audience
            self.expiration = expiration != nil ? Int(expiration!.timeIntervalSince1970) : nil
            self.notBefore = notBefore != nil ? Int(notBefore!.timeIntervalSince1970) : nil
            self.issuedAt = issuedAt != nil ? Int(issuedAt!.timeIntervalSince1970) : nil
            self.jwtID = jwtID
            self.miscellaneous = misc
        }


        enum CodingKeys: String, CodingKey, CaseIterable {
            case issuer = "iss"
            case subject = "sub"
            case audience = "aud"
            case expiration = "exp"
            case notBefore = "nbf"
            case issuedAt = "iat"
            case jwtID = "jti"
        }
        
        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)

            // Decode the known properties
            issuer = try container.decodeIfPresent(String.self, forKey: .issuer)
            subject = try container.decodeIfPresent(String.self, forKey: .subject)
            audience = try container.decodeIfPresent(String.self, forKey: .audience)
            expiration = try container.decodeIfPresent(Int.self, forKey: .expiration)
            notBefore = try container.decodeIfPresent(Int.self, forKey: .notBefore)
            issuedAt = try container.decodeIfPresent(Int.self, forKey: .issuedAt)
            jwtID = try container.decodeIfPresent(String.self, forKey: .jwtID)

            // Initialize the miscellaneous dictionary
            var misc = [String: AnyCodable]()

            // Extract all rawValues from CodingKeys for comparison
            let knownKeysRawValues = CodingKeys.allCases.map { $0.rawValue }

            // Dynamically decode keys not in CodingKeys
            let dynamicContainer = try decoder.container(keyedBy: DynamicCodingKey.self)
            for key in dynamicContainer.allKeys {
                // Convert DynamicCodingKey to String
                let keyString = key.stringValue
                
                // Skip keys that are part of the known CodingKeys
                if !knownKeysRawValues.contains(keyString) {
                    if let value = try? dynamicContainer.decode(AnyCodable.self, forKey: key) {
                        misc[keyString] = value
                    }
                }         
            }

            miscellaneous = misc.isEmpty ? nil : misc
        }
        
        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)

            // Encode known properties
            try container.encodeIfPresent(issuer, forKey: .issuer)
            try container.encodeIfPresent(subject, forKey: .subject)
            try container.encodeIfPresent(audience, forKey: .audience)
            try container.encodeIfPresent(expiration, forKey: .expiration)
            try container.encodeIfPresent(notBefore, forKey: .notBefore)
            try container.encodeIfPresent(issuedAt, forKey: .issuedAt)
            try container.encodeIfPresent(jwtID, forKey: .jwtID)

            // Dynamically encode the miscellaneous properties at the top level
            var dynamicContainer = encoder.container(keyedBy: DynamicCodingKey.self)
            if let misc = miscellaneous {
                for (key, value) in misc {
                    let codingKey = DynamicCodingKey(stringValue: key)!
                    try dynamicContainer.encode(value, forKey: codingKey)
                }
            }
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

    public static func verify(jwt: String) async throws {
        let parsedJwt = try parse(jwtString: jwt)
        
        if let exp = parsedJwt.payload.expiration, 
            Double(exp) > Date().timeIntervalSince1970 {
            throw Error.verificationFailed("JWT has expired")
        }

        guard let keyId = parsedJwt.header.keyID else {
            throw Error.verificationFailed("JWT has no keyID")
        }

        let dereferenceResult = await DIDUniversalResolver().dereference(didUrl: keyId)
        if let error = dereferenceResult.dereferencingMetadata.error {
            throw Error.verificationFailed(error)
        }

        guard let verificationMethod = dereferenceResult.contentStream?.value as? VerificationMethod,
            DIDUtility.isDidVerificationMethod(obj: verificationMethod) else {
            throw Error.verificationFailed("Expected kid in JWT header to dereference a DID Document Verification Method")
        }
        
        guard let publicKeyJwk = verificationMethod.publicKeyJwk else {
            throw Error.verificationFailed("Expected kid in JWT header to dereference to a DID Document Verification Method with publicKeyJwk")
        }

        if let algorithm = publicKeyJwk.algorithm, 
            algorithm.jwsAlgorithm != parsedJwt.header.algorithm {
            throw Error.verificationFailed("Expected alg in JWT header to match DID Document Verification Method alg")
        }

        let parts = jwt.components(separatedBy: ".")
        guard parts.count == 3 else {
            throw Error.verificationFailed("Malformed JWT. Expected 3 parts. Got \(parts.count)")
        }

        let signedData = "\(parts[0]).\(parts[1])";
        guard let signedDataBytes = try? signedData.base64decoded(),
            let signatureBytes = try? parts[2].base64decoded() else {
                throw Error.verificationFailed("Failed to base64 decode JWT signature")
        }
    // const signatureBytes = Convert.base64Url(encodedJwt.signature).toUint8Array();

        guard let isSignatureValid = try? Crypto.verify(payload: signedDataBytes, signature: signatureBytes, publicKey: publicKeyJwk),
            isSignatureValid else {
            throw Error.verificationFailed("Signature verification failed: Integrity mismatch")
        }

    }

    public struct ParsedJWT {
        let header: JWS.Header
        let payload: JWT.Claims

        public init(
            header: JWS.Header,
            payload: JWT.Claims
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
            JWT.Claims.self,
            from: try base64urlEncodedJwtPayload.decodeBase64Url())


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


// MARK: - DynamicCodingKey
// Define DynamicCodingKey to use for dynamic encoding
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
