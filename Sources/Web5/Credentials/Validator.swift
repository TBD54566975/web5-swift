import AnyCodable
import Foundation

public class SsiValidator {
    static func validateCredentialPayload(vc: VerifiableCredential) throws {
        try validate(context: vc.vcDataModel.context);
        try validate(vcType: vc.vcDataModel.type);
        try validate(credentialSubject: vc.vcDataModel.credentialSubject);
    }

    static func validate(context: [String]) throws {
        if (context.firstIndex(of: CredentialConstant.defaultContext) != 0) {
        throw SsiValidator.Error.invalidContext
        }
    }

    static func validate(vcType: [String]) throws {
        if (vcType.firstIndex(of: CredentialConstant.defaultVcType) != 0) {
        throw SsiValidator.Error.invalidVCType
        }
    }

    static func validate(credentialSubject: [String: AnyCodable]) throws {
        if credentialSubject.isEmpty {
            throw SsiValidator.Error.emptyCredentialSubject
        }
    }

}

extension SsiValidator {
    public enum Error: Swift.Error, LocalizedError {
        case invalidContext
        case invalidVCType
        case emptyCredentialSubject
        case invalidTimestamp

        public var errorDescription: String? {
            switch self {
            case .invalidContext:
                return NSLocalizedString("@context is missing default context", comment: "Validate credential payload")
            case .invalidVCType:
                return NSLocalizedString("type is missing default \(CredentialConstant.defaultVcType)", comment: "Validate credential payload")
            case .emptyCredentialSubject:
                return NSLocalizedString("credentialSubject must not be empty", comment: "Validate credential payload")
            case .invalidTimestamp:
                return NSLocalizedString("timestamp must be in ISO8601 format", comment: "Validate credential payload")
            }
        }
    }
}