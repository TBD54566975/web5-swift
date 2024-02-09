import Foundation

//typealias DIDMethodResolver = (String) async -> DIDResolutionResult

public enum DIDResolver {

//    private static var methodResolvers: [String: DIDMethodResolver] = [
//        DIDIon.methodName: DIDIon.resolve,
//        DIDJWK.methodName: DIDJWK.resolve,
//        DIDWeb.methodName: DIDWeb.resolve,
//    ]

    /// Resolves a DID URI to its DID Document
    public static func resolve(
        didURI: String
    ) async -> DIDResolutionResult {
//        guard let did = try? DID(didURI: didURI) else {
//            return DIDResolutionResult(error: .invalidDID)
//        }
//
//        guard let methodResolver = methodResolvers[did.methodName] else {
//            return DIDResolutionResult(error: .methodNotSupported)
//        }
//
//        return await methodResolver(didURI)
        fatalError("Not implemented")
    }
}
