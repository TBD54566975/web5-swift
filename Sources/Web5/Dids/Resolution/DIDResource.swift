import Foundation

public enum DIDResource: Codable, Equatable {
    case didDocument(DIDDocument)
    case verificationMethod(VerificationMethod)
    case service(Service)
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let didDocument = try? container.decode(DIDDocument.self) {
            self = .didDocument(didDocument)
        } else if let verificationMethod = try? container.decode(VerificationMethod.self) {
            self = .verificationMethod(verificationMethod)
        } else if let referencedId = try? container.decode(Service.self) {
            self = .service(referencedId)
        } else {
            throw DecodingError.typeMismatch(
                DIDResource.self,
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Expected either DIDDocument or VerificationMethod or Service"
                )
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .didDocument(didDocument):
            try container.encode(didDocument)
        case let .verificationMethod(verificationMethod):
            try container.encode(verificationMethod)
        case let .service(service):
            try container.encode(service)
        }
    }
    
    var value: Codable {
        switch self {
        case let .didDocument(didDocument):
            return didDocument
        case let .verificationMethod(verificationMethod):
            return verificationMethod
        case let .service(service):
            return service
        }
    }
}
