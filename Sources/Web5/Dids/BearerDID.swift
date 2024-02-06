import AnyCodable
import Foundation

// BearerDID is a composite type that combines a DID with a KeyManager containing keys
// associated to the DID. Together, these two components form a BearerDID that can be used to
// sign and verify data.
@dynamicMemberLookup
public struct BearerDID {

    public typealias Metadata = [String: AnyCodable]

    /// The `DID` object represented by this `BearerDID`
    public let did: DID

    /// The DIDDocument associated with this `BearerDID`
    public let document: DIDDocument

    /// The `KeyManager` which manages the keys for this DID
    public let keyManager: KeyManager

    /// Method-specific data associated with this `BearerDID`
    public let metadata: Metadata?

    /// Default initializer
    ///
    /// - Parameters:
    ///   - did: `DID` to create the `BearerDID` from
    ///   - document: `DIDDocument` associated with the provided `did`
    ///   - keyManager: `KeyManager` where the private key material for the provided `did` are stored
    ///   - metadata: Additional method-specific metadata to be included with the `BearerDID`
    init(
        did: DID,
        document: DIDDocument,
        keyManager: KeyManager,
        metadata: Metadata? = nil
    ) throws {
        self.did = did
        self.document = document
        self.keyManager = keyManager
        self.metadata = metadata
    }

    /// @dynamicMemberLookup allows us to access properties of the DID directly
    public subscript<T>(dynamicMember member: KeyPath<DID, T>) -> T {
        return did[keyPath: member]
    }

    /// Returns a `BearerDIDSigner` that can be used to sign messages, credentials, or arbitrary data
    ///
    /// If given, the `verificationMethodID` parameter is used to select a key from the
    /// verification methods present in the `DIDDocument`. If `verificationMethodID` is not
    /// provided, the first verificationMethod in the `DIDDocument` will be used.
    ///
    /// - Parameters:
    ///   - keyAlias: Alias of the key that will be used for
    public func getSigner(verificationMethodID: String? = nil) throws -> BearerDIDSigner {
        let verificationMethod: VerificationMethod?
        
        if let verificationMethodID {
            verificationMethod = document.verificationMethod?.first { $0.id == verificationMethodID }
        } else {
            verificationMethod = document.verificationMethod?.first
        }

        guard let verificationMethod else {
            throw Error.getSignerError("No verificationMethod found")
        }

        guard let publicKey = verificationMethod.publicKeyJwk else {
            throw Error.getSignerError("VerificationMethod \(verificationMethod.id) does not contain a publicKeyJwk")
        }

        let keyAlias = try keyManager.getDeterministicAlias(key: publicKey)
        return BearerDIDSigner(keyAlias: keyAlias, keyManager: keyManager)
    }

    /// Exports the `BearerDID` into a portable format that contains the DID's URI in addition
    /// to every private key associated with a verifification method.
    public func export() throws -> PortableDID {
        guard let exporter = keyManager as? KeyExporter else {
            throw Error.keyManagerNotExporter(keyManager)
        }

        let privateKeys: [Jwk] =
            try document
            .verificationMethod?
            .map { verificationMethod in
                guard let publicKey = verificationMethod.publicKeyJwk,
                    let keyAlias = try? keyManager.getDeterministicAlias(key: publicKey),
                    let privateKey = try? exporter.exportKey(keyAlias: keyAlias)
                else {
                    throw Error.exportError(
                        "Failed to export privateKey for verificationMethod \(verificationMethod.id)"
                    )
                }

                return privateKey
            } ?? []

        return PortableDID(
            uri: did.uri,
            document: document,
            privateKeys: privateKeys,
            metadata: metadata
        )
    }
}

// MARK: - Errors

extension BearerDID {

    public enum Error: LocalizedError {
        case keyManagerNotExporter(KeyManager)
        case keyManagerNotImporter(KeyManager)
        case getSignerError(String)
        case exportError(String)

        public var errorDescription: String? {
            switch self {
            case let .keyManagerNotExporter(keyManager):
                return "\(String(describing: type(of: keyManager))) does not support exporting keys"
            case let .keyManagerNotImporter(keyManager):
                return "\(String(describing: type(of: keyManager))) does not support importing keys"
            case let .getSignerError(reason):
                return "Error getting signer: \(reason)"
            case let .exportError(reason):
                return "Error exporting: \(reason)"
            }
        }
    }
}

// MARK: - BearerDIDSigner

public struct BearerDIDSigner {

    let keyAlias: String
    let keyManager: KeyManager

    public func sign<P>(payload: P) throws -> Data
    where P: DataProtocol {
        return try self.keyManager.sign(keyAlias: keyAlias, payload: payload)
    }
    
    public func verify<P, S>(payload: P, signature: S) throws -> Bool
    where P: DataProtocol, S: DataProtocol {
        let publicKey = try keyManager.getPublicKey(keyAlias: keyAlias)
        return try Crypto.verify(payload: payload, signature: signature, publicKey: publicKey)
    }
}
