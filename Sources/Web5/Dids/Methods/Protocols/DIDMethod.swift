import Foundation

/// Protocol defining the behaviors common to all DID methods
public protocol DIDMethod {
    
    /// The name of the DID method that this `DIDMethod` represents
    ///
    /// Example: In the DID URI `did:example:123`, the methodName is `example`
    static var methodName: String { get }

}
