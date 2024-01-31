import Foundation

public struct PortableDID: Codable {
    let uri: String
    let verificationMethods: [VerificationMethodKeyPair]

    public struct VerificationMethodKeyPair: Codable {
        let publicKey: Jwk
        let privateKey: Jwk

        enum CodingKeys: String, CodingKey {
            case publicKey = "publicKeyJwk"
            case privateKey = "privateKeyJwk"
        }
    }
}
