import Foundation
import AnyCodable

public enum CredentialConstant {
    public static let defaultContext = "https://www.w3.org/2018/credentials/v1"
    public static let defaultVcType = "VerifiableCredential";
}

public protocol VerifiableCredentialCreateOptions {
    /** The type of the credential, as an array of strings. */
    var type: [String] { get set }
    /** The issuer URI of the credential, as a string. */
    var issuer: String { get set }
    /** The subject URI of the credential, as a string. */  
    var subject: String { get set }
    /** The credential data, as a anycodable type. */
    var data: [String: AnyCodable]? { get set }
    /** The issuance date of the credential, as a string. */
    var issuanceDate: ISO8601Date? { get set }
    /** The expiration date of the credential, as a string. */
    var expirationDate: ISO8601Date? { get set }
    /** The evidence of the credential, as an dicationary. */
    var evidence: [String: AnyCodable]? { get set }
};

public struct VerifiableCredential {
    let vcDataModel: VCDataModel

    init(vcDataModel: VCDataModel) {
        self.vcDataModel = vcDataModel
    }

    public func type() -> String {
        return vcDataModel.type.last ?? ""
    }

    public func issuer() -> String {
        return vcDataModel.issuer
    }

    public func subject() -> String {
        if let id = vcDataModel.credentialSubject["id"]?.value as? String {
            return id
        }
        return ""
    }

    public func sign(did: BearerDID) async throws -> String {
        let claims = JWT.Claims(issuer: vcDataModel.issuer, 
                                subject: subject(), 
                                expiration: vcDataModel.expirationDate?.wrappedValue, 
                                notBefore: vcDataModel.issuanceDate.wrappedValue, 
                                issuedAt: Date(), 
                                jwtID: did.did.uri,
                                misc: ["vc": AnyCodable(vcDataModel)])
        let vcJwt = try JWT.sign(did: did, claims: claims)
        return vcJwt
    }

    public static func create(options: VerifiableCredentialCreateOptions) throws -> VerifiableCredential {
        var credentialSubject: [String: AnyCodable] = ["id": AnyCodable(options.subject)]
        if let data = options.data {
            for (key, value) in data {
                credentialSubject[key] = value
            }
            credentialSubject = credentialSubject.merging(data) { (_, new) in new}
        }

        let vcDataModel = VCDataModel(
            context: ["https://www.w3.org/2018/credentials/v1"],
            id: "urn:uuid:\(UUID().uuidString)",
            type: ["VerifiableCredential"] + options.type,
            issuer: options.issuer,
            issuanceDate: options.issuanceDate ?? ISO8601Date(wrappedValue: Date()),
            expirationDate: options.expirationDate,
            credentialSubject: credentialSubject,
            credentialStatus: nil,
            credentialSchema: nil,
            evidence: options.evidence
        )

        let vc = VerifiableCredential(vcDataModel: vcDataModel)
        try SsiValidator.validateCredentialPayload(vc: vc)
        return vc
    }

}