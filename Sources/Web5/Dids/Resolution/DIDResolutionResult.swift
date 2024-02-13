import Foundation

/// Representation of the result of a DID (Decentralized Identifier) resolution
///
/// [Specification Reference](https://www.w3.org/TR/did-core/#resolution)
public struct DIDResolutionResult: Codable, Equatable {

    /// The metadata associated with the DID resolution process.
    ///
    /// This includes information about the resolution process itself, such as any errors
    /// that occurred. If not provided in the constructor, it defaults to an empty
    /// `Metadata` object.
    public internal(set) var didResolutionMetadata: Metadata

    /// The resolved DID document, if available.
    ///
    /// This is the document that represents the resolved state of the DID. It may be `null`
    /// if the DID could not be resolved or if the document is not available.
    public internal(set) var didDocument: DIDDocument?

    /// The metadata associated with the DID document.
    ///
    /// This includes information about the document such as when it was created and
    /// any other relevant metadata. If not provided in the constructor, it defaults to an
    /// empty `DIDDocument.Metadata`.
    public internal(set) var didDocumentMetadata: DIDDocument.Metadata

    /// Default initializer
    init(
        didResolutionMetadata: Metadata = Metadata(),
        didDocument: DIDDocument? = nil,
        didDocumentMetadata: DIDDocument.Metadata = DIDDocument.Metadata()
    ) {
        self.didResolutionMetadata = didResolutionMetadata
        self.didDocument = didDocument
        self.didDocumentMetadata = didDocumentMetadata
    }

    public init(from decoder: Decoder) throws {
        let container: KeyedDecodingContainer<DIDResolutionResult.CodingKeys> = try decoder.container(
            keyedBy: DIDResolutionResult.CodingKeys.self
        )

        self.didResolutionMetadata =
            try container.decodeIfPresent(
                Metadata.self,
                forKey: DIDResolutionResult.CodingKeys.didResolutionMetadata
            ) ?? Metadata()
        self.didDocument = try container.decodeIfPresent(
            DIDDocument.self, forKey: DIDResolutionResult.CodingKeys.didDocument
        )
        self.didDocumentMetadata = try container.decode(
            DIDDocument.Metadata.self, forKey: DIDResolutionResult.CodingKeys.didDocumentMetadata
        )
    }
}

// MARK: - Errors

extension DIDResolutionResult {

    /// Errors that can occur during DID resolution process
    enum Error: String {
        /// The DID supplied does not conform to valid syntax
        case invalidDID = "invalidDid"
        /// The supplied method name is not supported by the DID method and/or DID resolver implementation
        case methodNotSupported
        /// The DID resolver was unable to find the DID document resulting from the resolution request
        case notFound
        /// An invalid public key is detected during a DID operation
        case invalidPublicKey
        /// The byte length of a public key does not match the expected value
        case invalidPublicKeyLength
        /// The DID Document supplied does not conform to valid syntax
        case invalidDIDDocument
        /// The byte length of a DID document does not match the expected value
        case invalidDIDDocumentLength
        /// Verification of a signature failed during a DID resolution request
        case invalidSignature
        /// Something went wrong internally within the DID resolver
        case internalError
        /// The type of a public key is not supported by the DID method and/or DID resolver implementation
        case unsupportedPublicKey
    }

    /// Convenience initializer for creating a DID resolution result with an error
    init(error: Error) {
        self.init(
            didResolutionMetadata: Metadata(error: error.rawValue),
            didDocument: nil,
            didDocumentMetadata: DIDDocument.Metadata()
        )
    }
}

// MARK: - Metadata

extension DIDResolutionResult {

    /// A metadata structure consisting of values relating to the results of the
    /// DID resolution process which typically changes between invocations of the
    /// resolve and resolveRepresentation functions, as it represents data about
    /// the resolution process itself
    ///
    /// [Specification Reference](https://www.w3.org/TR/did-core/#dfn-didresolutionmetadata)
    public struct Metadata: Codable, Equatable {

        /// The Media Type of the returned didDocumentStream. This property is
        /// REQUIRED if resolution is successful and if the resolveRepresentation
        /// function was called.
        public let contentType: String?

        /// The error code from the resolution process. This property is REQUIRED
        /// when there is an error in the resolution process. The value of this
        /// property MUST be a single keyword ASCII string. The possible property
        /// values of this field SHOULD be registered in the
        /// [DID Specification Registries](https://www.w3.org/TR/did-spec-registries/#error)
        public let error: String?

        init(
            contentType: String? = nil,
            error: String? = nil
        ) {
            self.contentType = contentType
            self.error = error
        }
    }
}
