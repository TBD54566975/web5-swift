import Foundation

public struct DIDUniversalResolver {

    // MARK: Static Properties

    private static var methodResolvers: [String: DIDMethodResolver] = {
        let defaultResolvers: [DIDMethodResolver] = [
            DIDDHT.Resolver(),
            DIDJWK.Resolver(),
            DIDIon.Resolver(),
            DIDWeb.Resolver()
        ]

        return defaultResolvers.reduce(into: [String: DIDMethodResolver]()) { result, resolver in
            result[resolver.methodName] = resolver
        }
    }()

    // MARK: Public Static Functions

    /// Register a `DIDMethodResolver` for custom resolution of a DID method.
    ///
    /// Certain DID methods can be resolved in a customized fashion, using a different configuration options
    /// to determine various aspects of the resolution process. If a customized resolution experience is desired,
    /// create a new `DIDMethodResolver` with the custom configuration options and register it using this function.
    ///
    /// If a resolver for the same method name already exists, it will be replaced.
    ///
    /// - Parameters:
    ///   - resolver: The `DIDMethodResolver` to add
    public static func register(resolver: DIDMethodResolver) {
        methodResolvers[resolver.methodName] = resolver
    }

    private let dereferencer: DIDURIDereference

    init( dereferencer: DIDURIDereference = DIDUniversalResolver.DIDDereferencer()) {
        self.dereferencer = dereferencer
    }

    public func resolve(didURI: String, options: DidResolutionOptions? = nil) async -> DIDResolutionResult {
        await dereferencer.resolver.resolve(didURI: didURI, options: options)
    }
   
    public func dereference(didUrl: String, options: DidDereferencingOptions? = nil) async -> DIDDereferencingResult {
        await dereferencer.dereference(didUrl: didUrl, options: options)
    }
}

// MARK: - DIDResolver & DIDDereferencer

extension DIDUniversalResolver {
    struct DIDResolver: DIDURIResolve {
        public func resolve(didURI: String, options: DidResolutionOptions? = nil) async -> DIDResolutionResult {
            guard let did = try? DID(didURI: didURI) else {
                return DIDResolutionResult(error: .invalidDID)
            }

            guard let methodResolver = DIDUniversalResolver.methodResolvers[did.methodName] else {
                return DIDResolutionResult(error: .methodNotSupported)
            }

            return await methodResolver.resolve(didURI: didURI)
        }
    }

    struct DIDDereferencer: DIDURIDereference {

        var resolver: DIDURIResolve

        init(resolver: DIDURIResolve = DIDUniversalResolver.DIDResolver()) {
            self.resolver = resolver
        }

        public func dereference(didUrl: String, options: DidDereferencingOptions? = nil) async -> DIDDereferencingResult {

            // Make sure DID can parse to its struct
            guard let parsedDidUrl = try? DID(didURI: didUrl) else {
                return DIDDereferencingResult(error: DID.Error.invalidURI)
            }

            let didResolutionResult = await resolver.resolve(didURI: parsedDidUrl.uriWithoutQueryAndFragment, options: nil)

            guard let didDocument = didResolutionResult.didDocument else {
                return DIDDereferencingResult(errorString: DIDResolutionResult.Error.invalidDIDDocument.rawValue)
            }

            if (parsedDidUrl.fragment == nil || parsedDidUrl.query != nil) {
                let metaData = DIDDereferencingMetadata(contentType: "application/did+json")
                return DIDDereferencingResult(dereferencingMetadata: metaData, 
                                            contentStream: DIDResource.didDocument(didDocument),
                                            contentMetadata: didResolutionResult.didDocumentMetadata)
            }       

            let parsedDidUrlFragment = parsedDidUrl.fragment!

            // Create a set of possible id matches. The DID spec allows for an id to be the entire
            // did#fragment or just #fragment.
            // @see {@link }https://www.w3.org/TR/did-core/#relative-did-urls | Section 3.2.2, Relative DID URLs}.
            // Using a Set for fast string comparison since some DID methods have long identifiers.
            let idSet: Set<String> = [didUrl, parsedDidUrlFragment, "#\(parsedDidUrlFragment)"];

            var didResource: DIDResource? = nil
            
            if let vms = didDocument.verificationMethod {
                for vm in vms where idSet.contains(vm.id) {
                    didResource = DIDResource.verificationMethod(vm)
                    break                    
                }
            }
            
            if let services = didDocument.service {
                for service in services where idSet.contains(service.id) {
                    didResource = DIDResource.service(service)
                    break
                }
            }

            if let didResource = didResource {
                let metaData = DIDDereferencingMetadata(contentType: "application/did+json")
                // To DO:
                // Js universal-resolver.ts here put the didResolutionMetadata into contentMetadata
                // check with TBD teams
                return DIDDereferencingResult(dereferencingMetadata: metaData,
                                            contentStream: didResource,
                                            contentMetadata: didResolutionResult.didDocumentMetadata)
            } else {
                return DIDDereferencingResult(error: DID.Error.notFound)
            }
        }
    }
}