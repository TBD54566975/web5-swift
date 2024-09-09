import Foundation
import CryptoKit
import SwiftCBOR
import Base32
import Base58Swift
import VarInt

enum VerificationError: Error {
    case invalidCredential
    case issuerNotTrusted
    case credentialTypeNotAllowed
    case networkError(Error)
}

struct Issuer: Codable {
    let id: String
    let name: String
    let credentialTypes: [String]
}

struct TruAgeConfiguration: Codable {
    let trustedIssuers: [Issuer]
}

struct VerificationResult {
    let verified: Bool
    let credential: [String: Any]?
    let issuer: String?
    let overAge: Bool?
}

// Verifies QR code text containing a `VP1-` header and a base32-encoded
func verifyQrCodeText(qrCodeText: String, minAge: Int = 21) throws -> VerificationResult {
    do {
        // Decode the QR code text and get the CBOR map
        let cborMap = try fromQrCodeText(expectedHeader: "VP1-", text: qrCodeText)
        
        print("Decoded CBOR Map: \(String(describing: cborMap))")
        
        // Extract and convert fields from CBOR map
        guard let vcMap = cborMap[CBOR.unsignedInt(124)] else {
            throw VerificationError.invalidCredential
        }
        
        let verifiableCredentialId = try CBORUtils.convertToUuid(vcMap[CBOR.unsignedInt(112)]!)
        print("Verifiable Credential ID: \(verifiableCredentialId)")

        let issuanceDate = CBORUtils.convertToRfc3339Datetime(vcMap[CBOR.unsignedInt(164)]!)
        print("Issuance Date: \(issuanceDate)")

        let expirationDate = CBORUtils.convertToRfc3339Datetime(vcMap[CBOR.unsignedInt(162)]!)
        print("Expiration Date: \(expirationDate)")

        let issuer = try CBORUtils.convertToDid(vcMap[CBOR.unsignedInt(168)]!)
        print("Issuer: \(issuer)")
        
        guard let subjectMap = vcMap[CBOR.unsignedInt(158)] else {
            throw VerificationError.invalidCredential
        }
        let concealedIdToken = try CBORUtils.convertToMultibase(subjectMap[CBOR.unsignedInt(138)]!)
        print("Concealed ID Token: \(concealedIdToken)")

        let overAge = try CBORUtils.convertToInt(subjectMap[CBOR.unsignedInt(148)]!)
        print("Over Age: \(overAge)")

        guard let proofMap = vcMap[CBOR.unsignedInt(114)] else {
            throw VerificationError.invalidCredential
        }
        let proofCreated = CBORUtils.convertToRfc3339Datetime(proofMap[CBOR.unsignedInt(182)]!)
        print("Proof Created: \(proofCreated)")

        let proofValue = try CBORUtils.convertToMultibase(proofMap[CBOR.unsignedInt(192)]!)
        print("Proof Value: \(proofValue)")

        let verificationMethod = try CBORUtils.convertToDid(proofMap[CBOR.unsignedInt(194)]!)
        print("Verification Method: \(verificationMethod)")
        
        let payload = generatePayload(proofCreated: proofCreated, verificationMethod: verificationMethod, verifiableCredentialId: verifiableCredentialId, expirationDate: expirationDate, issuanceDate: issuanceDate, issuer: issuer, overAge: Int(overAge), concealedIdToken: concealedIdToken)
        
        let signature = try generateSignature(proofValue: proofValue)
        
        let publicKey = try generatePublicKey(verificationMethod: verificationMethod)
        
        let isValid = try Ed25519.verify(
            payload: payload,
            signature: signature,
            publicKey: publicKey
        )
        
        print("isValid: \(isValid)")

        return VerificationResult(
            verified: isValid,
            credential: [
                "id": verifiableCredentialId,
                "issuanceDate": issuanceDate,
                "expirationDate": expirationDate
            ],
            issuer: issuer,
            overAge: overAge >= minAge
        )

    } catch {
        print("Verification failed with error: \(error)")
        return VerificationResult(
            verified: false,
            credential: nil,
            issuer: nil,
            overAge: nil
        )
    }
}

// Function to verify the QR code credential issuer and credential type
func verifyIssuer(issuerDid: String, credentialType: String) async throws -> Bool {
    // Fetch the TruAge configuration object
    let truageConfig = try await fetchTrustedIssuers()
    
    // Check if the issuer is trusted
    guard let trustedIssuer = truageConfig.trustedIssuers.first(where: { $0.id == issuerDid }) else {
        throw VerificationError.issuerNotTrusted
    }
    
    // Check if the credential type is allowed for the trusted issuer
    if !trustedIssuer.credentialTypes.contains(credentialType) {
        throw VerificationError.credentialTypeNotAllowed
    }
    
    // If everything is correct, return true for success
    return true
}


// Function to fetch the trusted issuers from TruAge API
private func fetchTrustedIssuers() async throws -> TruAgeConfiguration {
    let urlString = "https://admin.sandbox.truage.dev/age/issuers"
    
    guard let url = URL(string: urlString) else {
        throw VerificationError.invalidCredential
    }
    
    do {
        let (data, _) = try await URLSession.shared.data(from: url)
        let configuration = try JSONDecoder().decode(TruAgeConfiguration.self, from: data)
        return configuration
    } catch {
        throw VerificationError.networkError(error)
    }
}

// Function to generate payload for the signature
private func generatePayload(proofCreated: String, verificationMethod: String, verifiableCredentialId: String, expirationDate: String, issuanceDate: String, issuer: String, overAge: Int, concealedIdToken: String) -> [UInt8] {
    let proofQuads = """
    _:c14n0 <http://purl.org/dc/terms/created> "\(proofCreated)"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    _:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2020> .
    _:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
    _:c14n0 <https://w3id.org/security#verificationMethod> <\(verificationMethod)> .
    """

    let vcQuads = """
    <\(verifiableCredentialId)> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/age#OverAgeTokenCredential> .
    <\(verifiableCredentialId)> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
    <\(verifiableCredentialId)> <https://www.w3.org/2018/credentials#credentialSubject> _:c14n0 .
    <\(verifiableCredentialId)> <https://www.w3.org/2018/credentials#expirationDate> "\(expirationDate)"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    <\(verifiableCredentialId)> <https://www.w3.org/2018/credentials#issuanceDate> "\(issuanceDate)"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    <\(verifiableCredentialId)> <https://www.w3.org/2018/credentials#issuer> <\(issuer)> .
    _:c14n0 <https://w3id.org/age#overAge> "\(overAge)"^^<http://www.w3.org/2001/XMLSchema#positiveInteger> .
    _:c14n0 <https://w3id.org/cit#concealedIdToken> "\(concealedIdToken)"^^<https://w3id.org/security#multibase> .
    """

    let proofQuadsHash = sha256(proofQuads)
    let vcQuadsHash = sha256(vcQuads)

    let message = proofQuadsHash + vcQuadsHash
    
    return message
}

// Function to generate signature
private func generateSignature(proofValue: String) throws -> Data {
    let slicedProofValue = String(proofValue.dropFirst())
    guard let decodedData = Base58.base58Decode(slicedProofValue) else {
        throw VerificationError.invalidCredential
    }
    return Data(decodedData)
}

// Function to generate public key
private func generatePublicKey(verificationMethod: String) throws -> Jwk {
    let components = verificationMethod.split(separator: "#")
    guard components.count > 1 else {
        throw VerificationError.invalidCredential
    }
    
    let fingerprint = String(components[1])
    let slicedFingerprint = String(fingerprint.dropFirst())
    
    guard let idBytes = Base58.base58Decode(slicedFingerprint) else {
        throw VerificationError.invalidCredential
    }
    
    let varInt = uVarInt(idBytes)
    let publicKeyBytes = Array(idBytes.dropFirst(varInt.bytesRead))
    
    guard publicKeyBytes.count == 32 else {
        throw VerificationError.invalidCredential
    }
    
    return try Ed25519.publicKeyFromBytes(Data(publicKeyBytes))
}

// Helper function to compute SHA-256 hash
private func sha256(_ input: String) -> [UInt8] {
    let data = Data(input.utf8)
    let hashed = SHA256.hash(data: data)
    return Array(hashed)
}
