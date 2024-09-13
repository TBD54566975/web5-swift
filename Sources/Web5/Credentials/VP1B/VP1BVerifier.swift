import Foundation

public struct VP1BVerifier {
    static let QR_PREFIX = "VP1-B"

    public static func verifyQRCode(qrcode: String) throws -> VP1B {
        let vp1b = try VP1B.from(qrcode: qrcode)
        try vp1b.verify()

        return vp1b
    }

    public static func verifyIssuer(credential: VP1BCredential) async throws -> VP1BIssuer {
        let issuers = try await VP1BIssuers.fetchIssuers()
        let issuer = try issuers.findIssuer(credential: credential)
        try issuer.verify()

        return issuer
    }
}
