import Foundation

/// `did:jwk` DID Method
public enum DIDJWK {

    public static let methodName = "jwk"

    /// Resolves a `did:jwk` URI into a `DIDResolutionResult`
    /// - Parameters:
    ///   - didURI: The DID URI to resolve
    /// - Returns: `DIDResolution.Result` containing the resolved DID Document
    public static func resolve(
        didURI: String
    ) async -> DIDResolutionResult {
        guard let did = try? DID(didURI: didURI),
            let jwk = try? JSONDecoder().decode(Jwk.self, from: try did.identifier.decodeBase64Url())
        else {
            return DIDResolutionResult(error: .invalidDID)
        }

        guard did.methodName == self.methodName else {
            return DIDResolutionResult(error: .methodNotSupported)
        }

        let didDocument = didDocument(did: did, publicKey: jwk)
        return DIDResolutionResult(didDocument: didDocument)
    }

    /// Options that can be provided to customize how a `did:jwk` is created
    public struct CreateOptions {

        /// Default options to use when creating a `did:jwk`
        public static let `default` = CreateOptions(
            algorithm: .ed25519
        )

        /// The algorithm to use when creating the backing key for the DID
        public let algorithm: CryptoAlgorithm

        public init(
            algorithm: CryptoAlgorithm
        ) {
            self.algorithm = algorithm
        }
    }

    /// Create a new `BearerDID` using the `did:jwk` method
    ///
    /// - Parameters:
    ///   - keyManager: `KeyManager` used to generate and store the keys associated to the DID
    ///   - options: Options configuring how the DIDJWK is created
    /// - Returns: `BearerDID` that represents the created DIDJWK
    public static func create(
        keyManager: KeyManager,
        options: CreateOptions = .default
    ) throws -> BearerDID {
        let keyAlias = try keyManager.generatePrivateKey(algorithm: options.algorithm)
        let publicKey = try keyManager.getPublicKey(keyAlias: keyAlias)
        let publicKeyBase64Url = try JSONEncoder().encode(publicKey).base64UrlEncodedString()

        let didURI = "did:jwk:\(publicKeyBase64Url)"
        let did = try DID(didURI: didURI)
        let document = Self.didDocument(did: did, publicKey: publicKey)

        return try BearerDID(
            did: did,
            document: document,
            keyManager: keyManager
        )
    }

    /// Import a `PortableDID` that represents a DIDJWK into a `BearerDID` that can be used
    /// to sign and verify data
    ///
    /// - Parameters:
    ///   - keyManager: `KeyManager` to place the imported private keys. Defaults to `InMemoryKeyManager`
    ///   - portableDID: `PortableDID` to import into a `BearerDID`
    /// - Returns: `BearerDID` that represents the imported DIDJWK
    public static func `import`(
        keyManager: KeyManager = InMemoryKeyManager(),
        portableDID: PortableDID
    ) throws -> BearerDID {
        let did = try DID(didURI: portableDID.uri)
        guard did.methodName == methodName else {
            throw Error.importError(
                "Expected PortableDID with DID method \(methodName), was provided \(did.methodName)")
        }

        guard let importer = keyManager as? KeyImporter else {
            throw Error.importError("KeyManager does not support importing keys")
        }

        // Import the privateKeys into the keyManager
        for privateKey in portableDID.privateKeys {
            _ = try importer.import(key: privateKey)
        }

        return try BearerDID(
            did: did,
            document: portableDID.document,
            keyManager: keyManager
        )
    }

    private static func didDocument(
        did: DID,
        publicKey: Jwk
    ) -> DIDDocument {
        let verifiationMethod = VerificationMethod(
            id: "\(did.uri)#0",
            type: "JsonWebKey2020",
            controller: did.uri,
            publicKeyJwk: publicKey
        )

        return DIDDocument(
            context: .list([
                .string("https://www.w3.org/ns/did/v1"),
                .string("https://w3id.org/security/suites/jws-2020/v1"),
            ]),
            id: did.uri,
            verificationMethod: [verifiationMethod],
            assertionMethod: [.referenced(verifiationMethod.id)],
            authentication: [.referenced(verifiationMethod.id)],
            capabilityDelegation: [.referenced(verifiationMethod.id)],
            capabilityInvocation: [.referenced(verifiationMethod.id)]
        )
    }
}

// MARK: - Errors

extension DIDJWK {
    public enum Error: LocalizedError {
        case importError(String)

        public var errorDescription: String? {
            switch self {
            case let .importError(context):
                return "Import error: \(context)"
            }
        }
    }
}
