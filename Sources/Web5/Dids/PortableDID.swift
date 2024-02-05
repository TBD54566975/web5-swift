import AnyCodable
import Foundation

/// A representation of a `BearerDID` that can be moved imported/exported.
///
/// `PortableDID` bundles all of the necessary information for a `BearerDID`,
/// enabling the usage of the DID in different context. This format is compatible
/// and interoperable across all Web5 programming languages.
public struct PortableDID: Codable {

    public typealias Metadata = [String: AnyCodable]

    /// URI of DID
    let uri: String

    /// `DIDDocument` of the DID
    let document: DIDDocument

    /// Private keys that correspond to the public keys present in the `document`
    let privateKeys: [Jwk]

    /// Additional DID method specific information to be included
    let metadata: Metadata?
}
