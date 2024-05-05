import Foundation

/**
 * Represents metadata related to the process of DID dereferencing.
 *
 * This type includes fields that provide information about the outcome of a DID dereferencing operation,
 * including the content type of the returned resource and any errors that occurred during the dereferencing process.
 *
 * @see {@link https://www.w3.org/TR/did-core/#did-url-dereferencing-metadata | DID Core Specification, § DID URL Dereferencing Metadata}
 */
public struct DIDDereferencingMetadata: Codable, Equatable {
  /**
   * The Media Type of the returned contentStream SHOULD be expressed using this property if
   * dereferencing is successful.
   */
  var contentType: String?

  /**
   * The error code from the dereferencing process. This property is REQUIRED when there is an
   * error in the dereferencing process. The value of this property MUST be a single keyword
   * expressed as an ASCII string. The possible property values of this field SHOULD be registered
   * in the {@link https://www.w3.org/TR/did-spec-registries/ | DID Specification Registries}.
   * The DID Core specification defines the following common error values:
   *
   * - `invalidDidUrl`: The DID URL supplied to the DID URL dereferencing function does not conform
   *                    to valid syntax.
   * - `notFound`: The DID URL dereferencer was unable to find the `contentStream` resulting from
   *               this dereferencing request.
   *
   * @see {@link https://www.w3.org/TR/did-core/#did-url-dereferencing-metadata | DID Core Specification, § DID URL Dereferencing Metadata}
   */
  var error: String?

}


/**
 * Represents the result of a DID dereferencing operation.
 *
 * This type encapsulates the outcomes of the DID URL dereferencing process, including metadata
 * about the dereferencing operation, the content stream retrieved (if any), and metadata about the
 * content stream.
 *
 * @see {@link https://www.w3.org/TR/did-core/#did-url-dereferencing | DID Core Specification, § DID URL Dereferencing}
 */
public struct DIDDereferencingResult: Codable {
  /**
   * A metadata structure consisting of values relating to the results of the DID URL dereferencing
   * process. This structure is REQUIRED, and in the case of an error in the dereferencing process,
   * this MUST NOT be empty. Properties defined by this specification are in 7.2.2 DID URL
   * Dereferencing Metadata. If the dereferencing is not successful, this structure MUST contain an
   * `error` property describing the error.
   */
    var dereferencingMetadata: DIDDereferencingMetadata

  /**
   * If the `dereferencing` function was called and successful, this MUST contain a resource
   * corresponding to the DID URL. The contentStream MAY be a resource such as:
   *   - a DID document that is serializable in one of the conformant representations
   *   - a Verification Method
   *   - a service.
   *   - any other resource format that can be identified via a Media Type and obtained through the
   *     resolution process.
   *
   * If the dereferencing is unsuccessful, this value MUST be empty.
   */
    var contentStream: DIDResource?

  /**
   * If the dereferencing is successful, this MUST be a metadata structure, but the structure MAY be
   * empty. This structure contains metadata about the contentStream. If the contentStream is a DID
   * document, this MUST be a didDocumentMetadata structure as described in DID Resolution. If the
   * dereferencing is unsuccessful, this output MUST be an empty metadata structure.
   */
    var contentMetadata: DIDDocument.Metadata
    
}

extension DIDDereferencingResult {
    init(error: Error) {
        self.init(
            dereferencingMetadata: DIDDereferencingMetadata(error: error.localizedDescription),
            contentStream: nil,
            contentMetadata: DIDDocument.Metadata()
        )
    }

    init(errorString: String) {
        self.init(
            dereferencingMetadata: DIDDereferencingMetadata(error: errorString),
            contentStream: nil,
            contentMetadata: DIDDocument.Metadata()
        )
    }
}
