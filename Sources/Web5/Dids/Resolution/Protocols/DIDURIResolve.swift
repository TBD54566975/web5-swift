import Foundation

public protocol DIDMediaCallerPreference {
   /**
   * The Media Type that the caller prefers for the returned representation of the DID Document.
   *
   * This property is REQUIRED if the `resolveRepresentation` function was called. This property
   * MUST NOT be present if the `resolve` function was called.
   *
   * The value of this property MUST be an ASCII string that is the Media Type of the conformant
   * representations. The caller of the `resolveRepresentation` function MUST use this value when
   * determining how to parse and process the `didDocumentStream` returned by this function into the
   * data model.
   *
   * @see {@link https://www.w3.org/TR/did-core/#did-resolution-options | DID Core Specification, § DID Resolution Options}
   */
  var accept: String? { get set }
}

public protocol DidResolutionOptions: DIDMediaCallerPreference {}

public protocol DidDereferencingOptions: DIDMediaCallerPreference {}

public protocol DIDURIResolve {
    func resolve(didURI: String, options: DidResolutionOptions?) async -> DIDResolutionResult
}

public protocol DIDURIDereference {
    var resolver: DIDURIResolve { get }
    func dereference(didUrl: String, options: DidDereferencingOptions?) async -> DIDDereferencingResult
}