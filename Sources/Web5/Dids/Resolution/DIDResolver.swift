import Foundation

public enum DIDResolver {

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
    public static func register(
        resolver: DIDMethodResolver
    ) {
        methodResolvers[resolver.methodName] = resolver
    }

    /// Resolves a DID URI to its DID Document
    public static func resolve(
        didURI: String
    ) async -> DIDResolutionResult {
        guard let did = try? DID(didURI: didURI) else {
            return DIDResolutionResult(error: .invalidDID)
        }

        guard let methodResolver = methodResolvers[did.methodName] else {
            return DIDResolutionResult(error: .methodNotSupported)
        }

        return await methodResolver.resolve(didURI: didURI)
    }
}
