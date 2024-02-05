import Foundation

/// Protocol defining all common behaviors required for every DID Method
public protocol DIDMethod {

    /// The name of the DID Method.
    ///
    /// For example, in the DID URI `did:example:123456`, `example` would be the method name.
    static var methodName: String { get }
}
