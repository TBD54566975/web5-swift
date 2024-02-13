import Foundation

/// Decentralized Identifier (DID) Document
///
/// A set of data describing the DID subject including mechanisms such as:
///  * cryptographic public keys - used to authenticate itself and prove association
///  with the DID
///  * services - means of communicating or interacting with the DID subject or associated
///   entities via one or more service endpoints. Examples include discovery services, agent
///   services, social networking services, file storage services, and verifiable credential
///   repository services.
///
/// A DID Document can be retrieved by _resolving_ a DID URI
public struct DIDDocument: Codable, Equatable {

    public internal(set) var context: Context?

    /// The DID URI for a particular DID subject is expressed using the id property in the DID document.
    public internal(set) var id: String

    /// A DID subject can have multiple identifiers for different purposes, or at
    /// different times. The assertion that two or more DIDs (or other types of URI)
    /// refer to the same DID subject can be made using the alsoKnownAs property.
    public internal(set) var alsoKnownAs: [String]?

    /// A DID controller is an entity that is authorized to make changes to a
    /// DID document. The process of authorizing a DID controller is defined
    /// by the DID method.
    public internal(set) var controller: OneOrMany<String>?

    /// Cryptographic public keys, which can be used to authenticate or authorize
    /// interactions with the DID subject or associated parties.
    ///
    /// [Specification Reference](https://www.w3.org/TR/did-core/#verification-methods)
    public internal(set) var verificationMethod: [VerificationMethod]?

    /// Services are used in DID documents to express ways of communicating with
    /// the DID subject or associated entities.
    /// A service can be any type of service the DID subject wants to advertise.
    ///
    /// [Specification Reference](https://www.w3.org/TR/did-core/#services)
    public internal(set) var service: [Service]?

    /// The assertionMethod verification relationship is used to specify how the
    /// DID subject is expected to express claims, such as for the purposes of
    /// issuing a Verifiable Credential
    ///
    /// [Specification Reference](https://www.w3.org/TR/did-core/#assertion)
    public internal(set) var assertionMethod: [EmbeddedOrReferencedVerificationMethod]?

    /// `assertionMethod`, dereferencing any `VerificationMethod`s that are referenced
    public var assertionMethodDereferenced: [VerificationMethod]? {
        assertionMethod?.compactMap { $0.dereferenced(with: self) }
    }

    /// The authentication verification relationship is used to specify how the
    /// DID subject is expected to be authenticated, for purposes such as logging
    /// into a website or engaging in any sort of challenge-response protocol.
    ///
    /// [Specification Reference](https://www.w3.org/TR/did-core/#authentication)
    public internal(set) var authentication: [EmbeddedOrReferencedVerificationMethod]?

    /// `authentication`, dereferencing any `VerificationMethod`s that are referenced
    public var authenticationDereferenced: [VerificationMethod]? {
        authentication?.compactMap { $0.dereferenced(with: self) }
    }

    /// The keyAgreement verification relationship is used to specify how an
    /// entity can generate encryption material in order to transmit confidential
    /// information intended for the DID subject, such as for the purposes of
    /// establishing a secure communication channel with the recipient
    ///
    /// [Specification Reference](https://www.w3.org/TR/did-core/#key-agreement)
    public internal(set) var keyAgreement: [EmbeddedOrReferencedVerificationMethod]?

    /// `authentication`, dereferencing any `VerificationMethod`s that are referenced
    public var keyAgreementDereferenced: [VerificationMethod]? {
        keyAgreement?.compactMap { $0.dereferenced(with: self) }
    }

    /// The capabilityDelegation verification relationship is used to specify a
    /// mechanism that might be used by the DID subject to delegate a
    /// cryptographic capability to another party, such as delegating the
    /// authority to access a specific HTTP API to a subordinate.
    ///
    /// [Specification Reference](https://www.w3.org/TR/did-core/#capability-delegation)
    public internal(set) var capabilityDelegation: [EmbeddedOrReferencedVerificationMethod]?

    /// `capabilityDelegation`, dereferencing any `VerificationMethod`s that are referenced
    public var capabilityDelegationDereferenced: [VerificationMethod]? {
        capabilityDelegation?.compactMap { $0.dereferenced(with: self) }
    }

    /// The capabilityInvocation verification relationship is used to specify a
    /// verification method that might be used by the DID subject to invoke a
    /// cryptographic capability, such as the authorization to update the
    /// DID Document
    ///
    /// [Specification Reference](https://www.w3.org/TR/did-core/#capability-invocation)
    public internal(set) var capabilityInvocation: [EmbeddedOrReferencedVerificationMethod]?

    /// `capabilityInvocation`, dereferencing any `VerificationMethod`s that are referenced
    public var capabilityInvocationDereferenced: [VerificationMethod]? {
        capabilityInvocation?.compactMap { $0.dereferenced(with: self) }
    }

    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case id
        case alsoKnownAs
        case controller
        case verificationMethod
        case service
        case assertionMethod
        case authentication
        case keyAgreement
        case capabilityDelegation
        case capabilityInvocation
    }

    /// Contains metadata about the DID document contained in the didDocument
    /// property. This metadata typically does not change between invocations of
    /// the resolve and resolveRepresentation functions unless the DID document
    /// changes, as it represents metadata about the DID document.
    ///
    /// [Specification Reference](https://www.w3.org/TR/did-core/#dfn-diddocumentmetadata)
    public struct Metadata: Codable, Equatable {

        /// Timestamp of the Create operation. The value of the property MUST be a
        /// string formatted as an XML Datetime normalized to UTC 00:00:00 and
        /// without sub-second decimal precision. For example: 2020-12-20T19:17:47Z.
        public internal(set) var created: String?

        /// Timestamp of the last Update operation for the document version which was
        /// resolved. The value of the property MUST follow the same formatting rules
        /// as the created property. The updated property is omitted if an Update
        /// operation has never been performed on the DID document. If an updated
        /// property exists, it can be the same value as the created property
        /// when the difference between the two timestamps is less than one second.
        public internal(set) var updated: String?

        /// If a DID has been deactivated, DID document metadata MUST include this
        /// property with the boolean value true. If a DID has not been deactivated,
        /// this property is OPTIONAL, but if included, MUST have the boolean value
        /// false.
        public internal(set) var deactivated: Bool?

        /// Indicates the version of the last Update operation for the document version
        /// which was resolved.
        public internal(set) var versionId: String?

        /// Indicates the timestamp of the next Update operation. The value of the
        /// property MUST follow the same formatting rules as the created property.
        public internal(set) var nextUpdate: String?

        /// If the resolved document version is not the latest version of the document.
        /// It indicates the timestamp of the next Update operation. The value of the
        /// property MUST follow the same formatting rules as the created property.
        public internal(set) var nextVersionId: String?

        /// A DID method can define different forms of a DID that are logically
        /// equivalent. An example is when a DID takes one form prior to registration
        /// in a verifiable data registry and another form after such registration.
        /// In this case, the DID method specification might need to express one or
        /// more DIDs that are logically equivalent to the resolved DID as a property
        /// of the DID document. This is the purpose of the equivalentId property.
        public internal(set) var equivalentId: [String]?

        /// The canonicalId property is identical to the equivalentId property except:
        /// * It is associated with a single value rather than a set
        /// * The DID is defined to be the canonical ID for the DID subject within
        ///   the scope of the containing DID document.
        public internal(set) var canonicalId: String?

        /// Types for DIDs that support type indexing.
        public internal(set) var types: [Int]?
    }
}

/// A DID document can express verification methods, such as cryptographic
/// public keys, which can be used to authenticate or authorize interactions
/// with the DID subject or associated parties. For example,
/// a cryptographic public key can be used as a verification method with
/// respect to a digital signature; in such usage, it verifies that the
/// signer could use the associated cryptographic private key
///
/// [Specification Reference](https://www.w3.org/TR/did-core/#verification-methods)
public struct VerificationMethod: Codable, Equatable {
    public internal(set) var id: String
    public internal(set) var type: String
    public internal(set) var controller: String
    public internal(set) var publicKeyJwk: Jwk?
    public internal(set) var publicKeyMultibase: String?

    /// Computed property that returns the absolute ID of the verification method.
    public var absoluteId: String {
        if id.starts(with: "#") {
            return controller + id
        } else {
            return id
        }
    }
}

/// Services are used in DID documents to express ways of communicating with
/// the DID subject or associated entities.
/// A service can be any type of service the DID subject wants to advertise.
///
/// [Specification Reference](https://www.w3.org/TR/did-core/#services)
public struct Service: Codable, Equatable {
    public internal(set) var id: String
    public internal(set) var type: String
    public internal(set) var serviceEndpoint: String
}

/// DID Documents can have embedded or referenced verification methods.
/// This enum is used to represent both cases, and is able to parse either from JSON.
public enum EmbeddedOrReferencedVerificationMethod: Codable, Equatable {
    case embedded(VerificationMethod)
    case referenced(String)

    func dereferenced(with didDocument: DIDDocument) -> VerificationMethod? {
        switch self {
        case let .embedded(verificationMethod):
            return verificationMethod
        case let .referenced(verificationMethodId):
            return didDocument.verificationMethod?.first(where: { $0.absoluteId.contains(verificationMethodId) })
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let verificationMethod = try? container.decode(VerificationMethod.self) {
            self = .embedded(verificationMethod)
        } else if let referencedId = try? container.decode(String.self) {
            self = .referenced(referencedId)
        } else {
            throw DecodingError.typeMismatch(
                EmbeddedOrReferencedVerificationMethod.self,
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Expected either VerificationMethod or String"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .embedded(verificationMethod):
            try container.encode(verificationMethod)
        case let .referenced(referencedId):
            try container.encode(referencedId)
        }
    }
}
