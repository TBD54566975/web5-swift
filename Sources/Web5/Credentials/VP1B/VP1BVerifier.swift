import Foundation

public struct VP1BVerifier {
    static let QR_PREFIX = "VP1-B"

    public static func verifyQRCode(qrcode: String) throws -> VP1B {
        let vp1b = try VP1B.from(qrcode: qrcode)

        let payload = VP1BUtils.generatePayload(from: vp1b)
        let signature = try VP1BUtils.generateSignature(from: vp1b)
        let publicKey = try VP1BUtils.generatePublicKey(from: vp1b)

        let isValid = try Ed25519.verify(
            payload: payload,
            signature: signature,
            publicKey: publicKey
        )

        // TODO: throw error if signature verification fails
        print("isValid: \(isValid)")

        return vp1b
    }

    public static func verifyIssuer(credential: VP1BCredential) async throws -> Bool {
        let issuers = try await VP1BIssuers.fetchIssuers()
        let issuer = try VP1BIssuers.findIssuer(for: credential, in: issuers)

        return try VP1BIssuers.isValidCredentialType(issuer: issuer);
    }
}
