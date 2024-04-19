import AnyCodable
import Foundation

public class SsiValidator {
    static func validateCredentialPayload(vc: VerifiableCredential) throws {
        try validate(context: vc.vcDataModel.context);
        try validate(vcType: vc.vcDataModel.type);
        try validate(credentialSubject: vc.vcDataModel.credentialSubject);
        try validate(timestamp: vc.vcDataModel.issuanceDate)
        if let expirationDate = vc.vcDataModel.expirationDate { try validate(timestamp: expirationDate) }
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

    static func validate(timestamp: String) throws {
        if !isValidISO8601(timestamp) {
            throw SsiValidator.Error.invalidTimestamp
        }
    }

    static func isValidISO8601(_ string: String) -> Bool {
        let formats = [ // Add more formats if needed
            "yyyy-MM-dd",
            "yyyy-MM-dd'T'HH:mm:ss",
            "yyyy-MM-dd'T'HH:mm:ss.SSS",
            "yyyy-MM-dd'T'HH:mm:ssZ",
            "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        ]
        
        for format in formats {
            let formatter = DateFormatter()
            formatter.dateFormat = format
            if formatter.date(from: string) != nil {
            return true
            }
        }
        return false
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