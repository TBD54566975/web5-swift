import Foundation
import SwiftCBOR
import Base32

public struct VP1B : Decodable {
    let credential: VP1BCredential

    static let QR_PREFIX = "VP1-B"

    static func from(qrcode: String) throws -> VP1B {
        guard !qrcode.isEmpty else {
            throw Error.invalidInput("The QR code must not be empty.")
        }

        guard qrcode.starts(with: QR_PREFIX) else {
            throw Error.invalidInput("The QR code must start with '\(QR_PREFIX)' prefix.")
        }

        // Remove the prefix and decode base32 (no padding)
        let base32Encoded = String(qrcode.dropFirst(QR_PREFIX.count))
        guard let cborEncoded = base32Decode(base32Encoded) else {
            throw Error.invalidEncoding
        }

        // Chop off the first 3 bytes
        let cborBytes = Array(cborEncoded.dropFirst(3))

        // Decode CBOR map
        guard let cborMap = try CBOR.decode(cborBytes) else {
            throw Error.invalidCBOR
        }

        guard let vcMap = cborMap[CBOR.unsignedInt(124)] else {
            throw Error.invalidCredential
        }

        return VP1B(credential: try VP1BCredential.from(vcMap))
    }

    func verify() throws {
        let payload = VP1BUtils.generatePayload(from: self)
        let signature = try VP1BUtils.generateSignature(from: self)
        let publicKey = try VP1BUtils.generatePublicKey(from: self)

        guard try Ed25519.verify(payload: payload, signature: signature, publicKey: publicKey) else {
            throw Error.invalidSignature
        }
    }

    func expanded() -> [String: Any] {
        return [
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiablePresentation",
            "verifiableCredential": credential.expanded()
        ]
    }

    func type() -> [String] {
        return ["VerifiablePresentation"]
    }
}

extension VP1B {
    public enum Error: LocalizedError, Equatable {
        case invalidInput(String)
        case invalidEncoding
        case invalidCBOR
        case invalidCredential
        case invalidSignature

        public var errorDescription: String? {
            switch self {
            case let .invalidInput(reason):
                return "Invalid Input: \(reason)"
            case .invalidEncoding:
                return "Invalid Encoding: Failed to decode the QR code."
            case .invalidCBOR:
                return "Invalid CBOR: Could not decode CBOR data."
            case .invalidCredential:
                return "Invalid Credential: Credential data is missing or incorrect."
            case .invalidSignature:
                return "Invalid Signature: Signature verification failed"
            }
        }
    }
}
