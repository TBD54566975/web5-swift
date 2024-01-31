import Foundation

/// Collection of functions that implement the `did:jwk` method
public enum DIDJWK {

    public static let methodName = "jwk"

    /// Options that can be provided to customize how a DIDJWK is created
    public struct CreateOptions {

        /// The algorithm to use when creating the backing key for the DID
        public let algorithm: CryptoAlgorithm

        /// Default Initializer
        /// - Parameters
        ///   - algorithm: The algorithm to use when creating the backing key for the DID.
        ///   Defaults to `.ed25519` if not specified.
        public init(
            algorithm: CryptoAlgorithm = .ed25519
        ) {
            self.algorithm = algorithm
        }
    }

    /// Create a new DIDJWK
    /// - Parameters:
    ///   - keyManager: `KeyManager` used to generate and store the keys associated to the DID
    ///   - options: Options configuring how the DIDJWK is created. Uses default if not specified.
    /// - Returns: `BearerDID` that represents the created DIDJWK
    public static func create(
        keyManager: KeyManager,
        options: CreateOptions = .init()
    ) throws -> BearerDID {
        let keyAlias = try keyManager.generatePrivateKey(algorithm: options.algorithm)
        let publicKey = try keyManager.getPublicKey(keyAlias: keyAlias)
        let publicKeyBase64Url = try JSONEncoder().encode(publicKey).base64UrlEncodedString()
        let didURI = "did:jwk:\(publicKeyBase64Url)"

        return try BearerDID(didURI: didURI, keyManager: keyManager)
    }

    /// Resolves a `did:jwk` URI into a `DIDResolutionResult`
    /// - Parameter didURI: The DID URI to resolve
    /// - Returns: `DIDResolution.Result` containing the resolved DID Document.
    public static func resolve(didURI: String) async -> DIDResolutionResult {
        guard let did = try? DID(didURI: didURI),
            let jwk = try? JSONDecoder().decode(Jwk.self, from: try did.identifier.decodeBase64Url())
        else {
            return DIDResolutionResult(error: .invalidDID)
        }

        guard did.methodName == self.methodName else {
            return DIDResolutionResult(error: .methodNotSupported)
        }

        let verifiationMethod = VerificationMethod(
            id: "\(did.uri)#0",
            type: "JsonWebKey2020",
            controller: did.uri,
            publicKeyJwk: jwk
        )

        let didDocument = DIDDocument(
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

        return DIDResolutionResult(didDocument: didDocument)
    }
}
