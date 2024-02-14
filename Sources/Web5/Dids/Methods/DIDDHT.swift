import DNS
import Foundation

/// `did:dht` DID Method
public enum DIDDHT: DIDMethod {

    public static let methodName = "dht"
}

// MARK: - DIDMethodResolver

extension DIDDHT {

    /// Resolver for the `did:dht` DID method
    public struct Resolver: DIDMethodResolver {

        // MARK: Types

        /// Options that can be configured for resolving `did:dht` DIDs
        public struct ResolutionOptions {

            /// The URI of a server involved in executing DID method operations. In the context of
            /// DID creation, the endpoint is expected to be a Pkarr relay.
            let gatewayURI: String

            /// Public Memberwise Initializer
            public init(
                gatewayURI: String
            ) {
                self.gatewayURI = gatewayURI
            }

            /// Default `ResolutionOptions`
            public static let `default` = ResolutionOptions(
                gatewayURI: "https://diddht.tbddev.org"
            )
        }

        // MARK: Properties

        public let methodName = DIDDHT.methodName

        /// The options to use for the resolution process
        public let options: ResolutionOptions

        // MARK: Lifecycle

        /// Initialize a new resolver for the `did:dht` method
        /// - Parameters:
        ///   - options: The options to use for the resolution process
        public init(
            options: ResolutionOptions = .default
        ) {
            self.options = options
        }

        // MARK: Public Functions

        /// Resolves a `did:dht` URI into a `DIDResolutionResult`
        /// - Parameters:
        ///   - didURI: The DID URI to resolve
        /// - Returns: `DIDResolution.Result` containing the resolved DID Document.
        public func resolve(
            didURI: String
        ) async -> DIDResolutionResult {
            guard let did = try? DID(didURI: didURI) else {
                return DIDResolutionResult(error: .invalidDID)
            }

            guard did.methodName == methodName else {
                return DIDResolutionResult(error: .methodNotSupported)
            }

            return await Document.resolve(did: did, gatewayURI: options.gatewayURI)
        }
    }
}

// MARK: - DIDDHT.Document

extension DIDDHT {

    /// `DIDDHT.Document` provides functionality for interacting with the DID document stored in
    /// Mainline DHT in support of DID DHT method create, resolve, update, and deactivate operations.
    /// 
    /// This class includes methods for retrieving and publishing DID documents to and from the DHT,
    /// using DNS packet encoding and Pkarr relay servers.
    enum Document {

        /// Retrives a DID document and its metadata from the DHT network
        /// - Parameters:
        ///   - did: The DID whose document to retrieve
        ///   - gatewayURI: The DID DHT Gateway or Pkarr Relay URI
        /// - Returns: DIDResolutionResult containing the DID document and its metadata
        static func resolve(
            did: DID,
            gatewayURI: String
        ) async -> DIDResolutionResult {
            guard let identityKeyBytes = try? ZBase32.decode(did.identifier) else {
                return DIDResolutionResult(error: .invalidPublicKey)
            }

            if identityKeyBytes.count != 32 {
                return DIDResolutionResult(error: .invalidPublicKeyLength)
            }

            guard let bep44Message = try? await DIDDHT.Document.pkarrGet(
                publicKeyBytes: identityKeyBytes,
                gatewayURI: gatewayURI
            ) else {
                return DIDResolutionResult(error: .notFound)
            }

            do {
                let dnsPacket = try parseBEP44GetMessage(bep44Message)
                var (didDocument, didDocumentMetadata) = try fromDNSPacket(did: did, dnsPacket: dnsPacket)
                didDocumentMetadata.versionId = String(bep44Message.seq)

                return DIDResolutionResult(
                    didDocument: didDocument,
                    didDocumentMetadata: didDocumentMetadata
                )
            } catch Error.resolutionError(let resolutionError) {
                // A specific resolution error occured.
                return DIDResolutionResult(error: resolutionError)
            } catch {
                // Some other error happened, treat it as an internal error
                return DIDResolutionResult(error: .internalError)
            }
        }

        /// Retrieves a signed BEP44Message from a DID DHT Gateway or Pkarr Relay server
        /// - Parameters:
        ///   - publicKeyBytes: The public key bytes of the identity key, zbase32 encoded
        ///   - gatewayURI: The DID DHT Gateway or Pkarr Relay URI
        /// - Returns: BEP44Message containing the signed DNS packet
        static func pkarrGet(
            publicKeyBytes: Data,
            gatewayURI: String
        ) async throws -> BEP44Message {
            let identifier = ZBase32.encode(publicKeyBytes)

            guard let baseURL = URL(string: gatewayURI),
                let relativeURL = URL(string: identifier, relativeTo: baseURL)
            else {
                throw Error.resolutionError(.notFound)
            }

            let (data, response) = try await URLSession.shared.data(from: relativeURL)
            guard let response = response as? HTTPURLResponse,
                (200...299).contains(response.statusCode)
            else {
                throw Error.resolutionError(.notFound)
            }

            if data.count < 72 {
                throw Error.resolutionError(.invalidDIDDocumentLength)
            }

            if data.count > 1072 {
                throw Error.resolutionError(.invalidDIDDocumentLength)
            }

            let seqData = data.subdata(in: 64..<72)
            let seq: Int64 = seqData.withUnsafeBytes { $0.load(as: Int64.self) }.bigEndian

            return BEP44Message(
                k: publicKeyBytes,
                seq: seq,
                sig: data.prefix(64),
                v: data.suffix(from: 72)
            )
        }

        /// Parses and verifies a BEP44 Get Message, converting it to a DNS packet
        /// - Parameters:
        ///   - message: BEP44Message to verify and parse
        /// - Returns: DNS packet represented by the BEP44Message
        static func parseBEP44GetMessage(_ message: BEP44Message) throws -> DNS.Message {
            let publicKey = try EdDSA.Ed25519.publicKeyFromBytes(message.k)
            let bencodedData = try (
                Bencode.encodeAsBytes("seq") +
                Bencode.encodeAsBytes(message.seq) +
                Bencode.encodeAsBytes("v") +
                Bencode.encodeAsBytes(message.v)
            )

            let isValid = try EdDSA.Ed25519.verify(
                payload: bencodedData,
                signature: message.sig,
                publicKey: publicKey
            )

            if !isValid {
                throw Error.resolutionError(.invalidSignature)
            }

            var message = try DNS.Message(deserialize: message.v)

            // DNS.Message(deserialize:) doesn't parse out each of the answer's TextRecord attributes,
            // and instead assumes there's only ever one value. Detect this, and parse out any other
            // attributes that may be separated by semicolons.
            message.answers = message.answers.map { answer in
                if var answer = answer as? TextRecord {
                    for (k, v) in answer.attributes {
                        let splitValue = v.components(separatedBy: DIDDHT.Constants.PROPERTY_SEPARATOR)
                        answer.attributes[k] = splitValue[0]

                        for i in 1..<splitValue.count {
                            let parts = splitValue[i].components(separatedBy: "=")
                            if parts.count == 2 {
                                answer.attributes[parts[0]] = parts[1]
                            }
                        }
                    }

                    return answer
                } else {
                    return answer
                }
            }

            return message
        }

        /// Converts a DNS packet into a DID Document and its associated metadata,
        /// according to the `did:dht` [spec](https://tbd54566975.github.io/did-dht-method/#dids-as-a-dns-packet)
        static func fromDNSPacket(
            did: DID,
            dnsPacket: DNS.Message
        ) throws -> (DIDDocument, DIDDocument.Metadata) {
            var idLookup = [String: String]()

            var alsoKnownAs = [String]()
            var controllers = [String]()
            var verificationMethods = [VerificationMethod]()
            var services = [Service]()
            var authentication: [EmbeddedOrReferencedVerificationMethod]?
            var assertionMethod: [EmbeddedOrReferencedVerificationMethod]?
            var capabilityDelegation: [EmbeddedOrReferencedVerificationMethod]?
            var capabilityInvocation: [EmbeddedOrReferencedVerificationMethod]?
            var keyAgreement: [EmbeddedOrReferencedVerificationMethod]?
            var types: [Int]?

            /// `did:dht` properties are ONLY present in DNS TXT records.
            /// Loop through the answers, only taking into consideration the text records.
            for case let answer as TextRecord in dnsPacket.answers {
                let dnsRecordID = String(answer.name.prefix { $0 != "." }.dropFirst())

                if dnsRecordID.hasPrefix("aka") {
                    // Process an also known as record
                    alsoKnownAs.append(contentsOf: answer.values)
                } else if dnsRecordID.hasPrefix("cnt") {
                    // Process a controller record
                    controllers.append(contentsOf: answer.values)
                } else if dnsRecordID.hasPrefix("k") {
                    // Process verification methods
                    let publicKeyBytes = try answer.attributes["k"]!.decodeBase64Url()
                    let namedCurve = RegisteredKeyType(rawValue: Int(answer.attributes["t"]!)!)

                    let publicKey: Jwk
                    switch namedCurve {
                    case .Ed25519:
                        publicKey = try EdDSA.Ed25519.publicKeyFromBytes(publicKeyBytes)
                    case .secp256k1:
                        publicKey = try ECDSA.Es256k.publicKeyFromBytes(publicKeyBytes)
                    default:
                        throw Error.resolutionError(.unsupportedPublicKey)
                    }

                    let methodID = "\(did.uri)#\(answer.attributes["id"]!)"
                    verificationMethods.append(
                        VerificationMethod(
                            id: methodID,
                            type: "JsonWebKey",
                            controller: answer.attributes["c"] ?? did.uri,
                            publicKeyJwk: publicKey
                        )
                    )

                    idLookup[dnsRecordID] = methodID
                } else if dnsRecordID.hasPrefix("s") {
                    // Process services
                    let id = "\(did.uri)#\(answer.attributes["id"]!)"
                    let serviceEndpoint = answer.attributes["se"]!
                    let type = answer.attributes["t"]!

                    services.append(
                        Service(
                            id: id,
                            type: type,
                            serviceEndpoint: serviceEndpoint
                        )
                    )
                } else if dnsRecordID.hasPrefix("typ") {
                    // Process DID DHT types
                    guard let values = answer.attributes["id"] else {
                        fatalError("types not found")
                    }

                    types = values.components(separatedBy: Constants.VALUE_SEPARATOR).compactMap { Int($0) }
                } else if dnsRecordID.hasPrefix("did") {
                    // Parse root record
                    func recordIDsToMethodIDs(data: String) -> [String] {
                        return data
                            .components(separatedBy: Constants.VALUE_SEPARATOR)
                            .compactMap { idLookup[String($0)] }
                    }

                    if let auth = answer.attributes["auth"] {
                        authentication = recordIDsToMethodIDs(data: auth).map { .referenced($0) }
                    }
                    if let asm = answer.attributes["asm"] {
                        assertionMethod = recordIDsToMethodIDs(data: asm).map { .referenced($0) }
                    }
                    if let del = answer.attributes["del"] {
                        capabilityDelegation = recordIDsToMethodIDs(data: del).map{ .referenced($0) }
                    }
                    if let inv = answer.attributes["inv"] {
                        capabilityInvocation = recordIDsToMethodIDs(data: inv).map { .referenced($0) }
                    }
                    if let agm = answer.attributes["agm"] {
                        keyAgreement = recordIDsToMethodIDs(data: agm).map { .referenced($0) }
                    }
                }
            }

            return (
                DIDDocument(
                    id: did.uri,
                    alsoKnownAs: alsoKnownAs,
                    controller: .many(controllers),
                    verificationMethod: verificationMethods,
                    service: services,
                    assertionMethod: assertionMethod,
                    authentication: authentication,
                    keyAgreement: keyAgreement,
                    capabilityDelegation: capabilityDelegation,
                    capabilityInvocation: capabilityInvocation
                ),
                DIDDocument.Metadata(
                    types: types
                )
            )
        }
    }

    /// Enumeration of the the types of keys that can be used in a DID DHT document.
    ///
    /// The DID DHT method supports various cryptographic key types. These key types are essential for
    /// the creation and management of DIDs and their associated cryptographic operations like signing
    /// and encryption. The registered key types are published in the DID DHT Registry and each is
    /// assigned a unique numerical value for use by client and gateway implementations.
    ///
    /// The registered key types are published in the
    /// [DID DHT Registry](https://did-dht.com/registry/index.html#key-type-index).
    enum RegisteredKeyType: Int {
        /// A public-key signature system using the EdDSA (Edwards-curve Digital Signature Algorithm) and Curve25519.
        case Ed25519 = 0

        /// A cryptographic curve used for digital signatures in a range of decentralized systems.
        case secp256k1 = 1

        /// Also known as P-256 or prime256v1, this curve is used for cryptographic operations and is widely
        /// supported in various cryptographic libraries and standards.
        case secp256r1 = 2
    }

    enum Constants {
        /// Character used to separate distinct elements or entries in the DNS packet representation of a DID Document.
        ///
        /// For example, verification methods, verification relationships, and services are separated by
        /// semicolons (`;`) in the root record:
        /// ```
        /// vm=k1;auth=k1;asm=k2;inv=k3;del=k3;srv=s1
        /// ```
        static let PROPERTY_SEPARATOR = ";"

        /// Character used to separate distinct values within a single element or entry in the DNS packet
        /// representation of a DID Document.
        ///
        /// For example, multiple key references for the `authentication` verification relationships are
        /// separated by commas (`,`):
        /// ```
        /// auth=0,1,2
        /// ```
        static let VALUE_SEPARATOR = ","
    }
}

// MARK: - BEP44Message

/// Represents a BEP44 message, which is used for storing and retrieving data in the Mainline DHT
/// network.
/// 
/// A BEP44 message is used primarily in the context of the DID DHT method for publishing and
/// resolving DID documents in the DHT network. This type encapsulates the data structure required
/// for such operations in accordance with BEP44.
/// 
/// See [BEP44](https://www.bittorrent.org/beps/bep_0044.html) for more information.
struct BEP44Message {

    /// The public key bytes of the Identity Key, which serves as the identifier in the DHT network for
    /// the corresponding BEP44 message.
    let k: Data

    /// The sequence number of the message, used to ensure the latest version of the data is retrieved
    /// and updated. It's a monotonically increasing number.
    let seq: Int64

    /// The signature of the message, ensuring the authenticity and integrity of the data. It's
    /// computed over the bencoded sequence number and value.
    let sig: Data

    /// The actual data being stored or retrieved from the DHT network, typically encoded in a format
    /// suitable for DNS packet representation of a DID Document.
    let v: Data
}

// MARK: - Errors

extension DIDDHT {
    enum Error: LocalizedError {
        case resolutionError(DIDResolutionResult.Error)

        public var errorDescription: String? {
            switch self {
            case let .resolutionError(error):
                return "Error resolving DID: \(error)"
            }
        }
    }
}
