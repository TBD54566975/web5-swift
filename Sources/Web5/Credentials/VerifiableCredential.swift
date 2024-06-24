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
    /** The issuance date of the credential, as a ISO8601Date. */
    var issuanceDate: ISO8601Date? { get set }
    /** The expiration date of the credential, as a ISO8601Date. */
    var expirationDate: ISO8601Date? { get set }
    /** The credential status lookup information. */
    var credentialStatus: StatusList2021Entry? { get set }
    /** The schema of the credential. */
    var credentialSchema: CredentialSchema? { get set }
    /** The evidence of the credential, as an array of dicationary. */
    var evidence: [[String: AnyCodable]]? { get set }
};

public struct VerifiableCredential: Equatable {

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
        let claims = JWT.Claims(issuer: did.did.uri, 
                                subject: subject(), 
                                expiration: vcDataModel.expirationDate?.wrappedValue, 
                                notBefore: vcDataModel.issuanceDate.wrappedValue, 
                                issuedAt: Date(), 
                                jwtID: vcDataModel.id,
                                misc: ["vc": AnyCodable(vcDataModel)])
        let vcJwt = try JWT.sign(did: did, claims: claims)
        return vcJwt
    }

    public static func create(options: VerifiableCredentialCreateOptions) throws -> VerifiableCredential {
        guard options.issuer.count > 0, options.subject.count > 0 else {
            throw Error.verificationFailed("Issuer and subject must be defined")
        }
        var credentialSubject: [String: AnyCodable] = ["id": AnyCodable(options.subject)]
        if let data = options.data {
            for (key, value) in data {
                credentialSubject[key] = value
            }
            credentialSubject = credentialSubject.merging(data) { (_, new) in new}
        }

        var context = [CredentialConstant.defaultContext]
        if options.credentialStatus != nil {
            context.append(StatusListConstant.defaultContext)
        }
        let vcDataModel = VCDataModel(
            context: context,
            id: "urn:uuid:\(UUID().uuidString)",
            type: ["VerifiableCredential"] + options.type,
            issuer: options.issuer,
            issuanceDate: options.issuanceDate ?? ISO8601Date(wrappedValue: Date()),
            expirationDate: options.expirationDate,
            credentialSubject: credentialSubject,
            credentialStatus: options.credentialStatus,
            credentialSchema: options.credentialSchema,
            evidence: options.evidence
        )

        let vc = VerifiableCredential(vcDataModel: vcDataModel)
        try SsiValidator.validateCredentialPayload(vc: vc)
        return vc
    }

}

// Verify
extension VerifiableCredential {
    // verify: Runs all verification checks.
    public static func verify(jwt: String) async throws {
        let payload = try await JWT.verify(jwt: jwt).payload
        try _verifyVCDataModel(payload: payload)
        try _verifyExpiration(payload: payload)
        try _verifyIssuer(payload: payload)
        try _verifyNotBeforeDate(payload: payload)
        try _verifySubject(payload: payload)
        try _verifyJwtId(payload: payload)
    }

    // verifyExpiration: Checks the VC expiration date to ensure it is still valid.
    private static func _verifyExpiration(payload: JWT.Claims) throws {
        guard let exp = payload.expiration else { return }

        guard let vcdm = try? getVcDataModel(payload: payload), 
            let vcExp = vcdm.expirationDate?.wrappedValue?.timeIntervalSince1970,
            Int(vcExp) == exp else {
            throw Error.verificationFailed("exp claim does not match expirationDate")
        }
    }

    private static func _verifyNotBeforeDate(payload: JWT.Claims) throws {
        guard let nbf = payload.notBefore else { return }

        // nbf cannot represent time in the future
        guard nbf <= Int(Date().timeIntervalSince1970) else {
            throw Error.verificationFailed("nbf claim is in the future")
        }

        // nbf MUST represent issuanceDate
        if let vcdm = try? getVcDataModel(payload: payload),
            let vcIss = vcdm.issuanceDate.wrappedValue?.timeIntervalSince1970, 
            nbf != Int(vcIss) {
                throw Error.verificationFailed("nbf claim does not match issuanceDate")
        }
    }

    // verifyTrustedIssuer: Will accept options for a list of trusted issuer dids ⚠️
    private static func _verifyIssuer(payload: JWT.Claims) throws {
        guard let vcdm = try? getVcDataModel(payload: payload), 
            let issuer = payload.issuer,
            vcdm.issuer == issuer else {
            throw Error.verificationFailed("iss claim does not match expected issuer")
        }
    }

    private static func _verifySubject(payload: JWT.Claims) throws {
        guard let subject = payload.subject else { return }

        guard let vcdm = try? getVcDataModel(payload: payload),
            vcdm.credentialSubject["id"]?.value as? String == subject else {
            throw Error.verificationFailed("sub claim does not match expected subject")
        }
    }

    private static func _verifyJwtId(payload: JWT.Claims) throws {
        guard let jwtID = payload.jwtID else { return }

        guard let vcdm = try? getVcDataModel(payload: payload),
            vcdm.id == jwtID else {
            throw Error.verificationFailed("jti claim does not match expected id")
        }
    
    }
    // verifySchema: Ensures that the VC conforms to a specified schema.
    // verifyVcDataModel: Verifies if it is a valid VC data model, confirming the VC's structural compliance with the relevant standards.
    private static func _verifyVCDataModel(payload: JWT.Claims) throws {
        let vcdm = try getVcDataModel(payload: payload)
        try SsiValidator.validate(context: vcdm.context)
        try SsiValidator.validate(vcType: vcdm.type)
        try SsiValidator.validate(credentialSubject: vcdm.credentialSubject)
    }

    private static func getVcDataModel(payload: JWT.Claims) throws -> VCDataModel {
        guard let anycodableVC = payload.miscellaneous?["vc"] as? AnyCodable,
               let dictionary = anycodableVC.value as? [String: Any],
               let jsonData = try? JSONSerialization.data(withJSONObject: dictionary, options: []),
               let vcDataModel = try? JSONDecoder().decode(VCDataModel.self, from: jsonData)
                 else {
            throw Error.verificationFailed("Expected vc in JWT payload")
         }
         return vcDataModel
    }

    // TO DO
    // verifyStatus: Checks if the status list credential exists and if it is valid or revoked.
    // verifyIntegrity: Performs a JWT integrity check to ensure it adheres to expected formatting and contains all necessary elements. These include header verification, payload structure, and encoding checks.
    // verifySignature: Cryptographic verification of the JWT's signature to confirm its authenticity. This involves resolving the issuer's DID, retrieving the corresponding public key, and using it to verify the signature against the JWT's payload. These include did resolution, signature verification and algorithm verification

}

// Parse
extension VerifiableCredential {
    public static func parse(jwt: String) throws -> VerifiableCredential {
        let jwt = try JWT.parse(jwtString: jwt)
        let vcDataModel = try getVcDataModel(payload: jwt.payload)
        let vc = VerifiableCredential(vcDataModel: vcDataModel)
        try SsiValidator.validateCredentialPayload(vc: vc)
        return vc
    }
}

extension VerifiableCredential {
    enum Error: Swift.Error, Equatable {
        case verificationFailed(String)
    }
}