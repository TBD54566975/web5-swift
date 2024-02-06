import Foundation

public enum DIDResolver {

    private static var methodResolvers: [String: any DIDMethodResolver.Type] = [
        DIDIon.methodName: DIDIon.self,
        DIDJWK.methodName: DIDJWK.self,
        DIDWeb.methodName: DIDWeb.self,
    ]

    /// Resolves a DID URI to its DID Document
    public static func resolve(didURI: String) async -> DIDResolutionResult {
        guard let did = try? DID(didURI: didURI) else {
            return DIDResolutionResult(error: .invalidDID)
        }

        guard let methodResolver = methodResolvers[did.methodName] else {
            return DIDResolutionResult(error: .methodNotSupported)
        }

        return await methodResolver.resolve(didURI: didURI)
    }
}
