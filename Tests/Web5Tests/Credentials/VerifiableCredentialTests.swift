import XCTest
import AnyCodable
@testable import Web5

class VerifiableCredentialTests: XCTestCase {
    struct TBDeveloper {
        let name: String
        let role: String
    }

    struct VCCOptions: VerifiableCredentialCreateOptions {
        var type: [String]
        var issuer: String
        var subject: String
        var issuanceDate: ISO8601Date?
        var expirationDate: ISO8601Date?
        var data: [String: AnyCodable]?
        var credentialSchema: CredentialSchema?
        var evidence: [[String: AnyCodable]]?
    }

    private func convert(source: [Any]) -> [[String: AnyCodable]] {
        var arr: [[String: AnyCodable]] = []
        source.forEach {
            let mirror = Mirror(reflecting: $0)
            var dictionary = [String: AnyCodable]()
            
            for case let (label?, value) in mirror.children {
                dictionary[label] = AnyCodable(value)
            }
            arr.append(dictionary)
        }
        return arr
    }

    func test_CreateVC() throws {
        
        struct StreetCredibility {
            let localRespect: String
            let legit: Bool
        }

        let issuerDid = try! DIDJWK.create();
        let sc = StreetCredibility(localRespect: "high", legit: true)
        let options = VCCOptions(type: ["StreetCred"], 
                                 issuer: issuerDid.did.uri, 
                                 subject: issuerDid.did.uri,
                                 data: convert(source: [sc]).first!)

        let vc = try VerifiableCredential.create(options: options)

        XCTAssertEqual(vc.issuer(), issuerDid.did.uri)
        XCTAssertEqual(vc.subject(), issuerDid.did.uri)
        XCTAssertEqual(vc.type(), "StreetCred")
        XCTAssertNotNil(vc.vcDataModel.issuanceDate)
        XCTAssertEqual(vc.vcDataModel.credentialSubject["id"]?.value as! String, issuerDid.did.uri)
        XCTAssertEqual(vc.vcDataModel.credentialSubject["localRespect"]?.value as! String, "high")
        XCTAssertEqual(vc.vcDataModel.credentialSubject["legit"]?.value as! Bool, true)

    }

    func test_createAndSignVCWithDidJWk() async throws {
        let issuerDid = try! DIDJWK.create();
        let options = VCCOptions(type: ["TBDeveloperCredential"], 
                                 issuer: issuerDid.did.uri, 
                                 subject: issuerDid.did.uri,
                                 data: convert(source: [TBDeveloper(name: "alice", role: "software engineer")]).first!)
        let vc = try VerifiableCredential.create(options: options)
        let vcJwt = try await vc.sign(did: issuerDid)
        try await VerifiableCredential.verify(jwt: vcJwt)
        let parsedVC = try VerifiableCredential.parse(jwt: vcJwt)
        for currentVC in [vc, parsedVC] {
            XCTAssertEqual(currentVC.issuer(), issuerDid.did.uri)
            XCTAssertEqual(currentVC.subject(), issuerDid.did.uri)
            XCTAssertEqual(currentVC.type(), "TBDeveloperCredential")
            XCTAssertNotNil(currentVC.vcDataModel.issuanceDate)
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["id"]?.value as! String, issuerDid.did.uri)
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["name"]?.value as! String, "alice")
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["role"]?.value as! String, "software engineer")
        }
    }

    func test_createAndSignKYCWithDidJwk() async throws {
        struct KYC {
            let id: String
            let country: String
            let tier: String
        }
        struct Schema {
            let id: String = "https://schema.org/PFI"
            let type: String = "JsonSchema"
        }
        struct Evidence {
            let kind: String
            let checks: [String]
        }

        let issuerDid = try! DIDJWK.create();
        let subjectDid = try DIDJWK.create()
        let evidences = [Evidence(kind: "document_verification", checks: ["passport", "utility_bill"]),
                                     Evidence(kind: "sanctions_check", checks: ["daily"])]
        let options = VCCOptions(type: ["KnowYourCustomerCred"], 
                                 issuer: issuerDid.did.uri, 
                                 subject: subjectDid.did.uri,
                                 issuanceDate: ISO8601Date(dateString: "2023-05-19T08:02:04Z"),
                                 expirationDate: ISO8601Date(dateString: "2055-05-19T08:02:04Z"),
                                 data: convert(source: [KYC(id: subjectDid.did.uri, country: "US", tier: "gold")]).first!,
                                 credentialSchema: CredentialSchema(id: "https://schema.org/PFI", type: "JsonSchema"),
                                 evidence: convert(source: evidences))

        let vc = try VerifiableCredential.create(options: options)
        let vcJwt = try await vc.sign(did: issuerDid)
        try await VerifiableCredential.verify(jwt: vcJwt)
        let parsedVC = try VerifiableCredential.parse(jwt: vcJwt)

        for currentVC in [vc, parsedVC] {
            XCTAssertEqual(currentVC.issuer(), issuerDid.did.uri)
            XCTAssertEqual(currentVC.subject(), subjectDid.did.uri)
            XCTAssertEqual(currentVC.type(), "KnowYourCustomerCred")
            XCTAssertEqual(currentVC.vcDataModel.issuanceDate.dateString, "2023-05-19T08:02:04Z")
            XCTAssertEqual(currentVC.vcDataModel.expirationDate?.dateString, "2055-05-19T08:02:04Z")
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["id"]?.value as! String, subjectDid.did.uri)
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["country"]?.value as! String, "US")
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["tier"]?.value as! String, "gold")
            XCTAssertEqual(currentVC.vcDataModel.credentialSchema?.id, "https://schema.org/PFI")
            XCTAssertEqual(currentVC.vcDataModel.credentialSchema?.type, "JsonSchema")
            XCTAssertEqual(currentVC.vcDataModel.evidence?.count, 2)
            XCTAssertEqual(currentVC.vcDataModel.evidence?[0]["kind"]?.value as! String, "document_verification")
            XCTAssertEqual(currentVC.vcDataModel.evidence?[0]["checks"]?.value as! [String], ["passport", "utility_bill"])
            XCTAssertEqual(currentVC.vcDataModel.evidence?[1]["kind"]?.value as! String, "sanctions_check")
            XCTAssertEqual(currentVC.vcDataModel.evidence?[1]["checks"]?.value as! [String], ["daily"])
        }
    }

    func test_createAndSignVCWithEvidence() async throws {
        struct Evidence {
            let id: String
            let type: [String]
            let verifier: String
            let evidenceDocument: String
            let subjectPresence: String
            let documentPresence: String
            let licenseNumber: String
        }

        let issuerDid = try! DIDJWK.create();
        let evidence = Evidence(id: "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231", 
                                            type: ["DocumentVerification"], 
                                            verifier: "https://example.edu/issuers/14", 
                                            evidenceDocument: "DriversLicense", 
                                            subjectPresence: "Physical", 
                                            documentPresence: "Physical", 
                                            licenseNumber: "123AB4567")
        let options = VCCOptions(type: ["TBDeveloperCredential"], 
                                 issuer: issuerDid.did.uri, 
                                 subject: issuerDid.did.uri,
                                 data: convert(source: [TBDeveloper(name: "bob", role: "test engineer")]).first!,
                                 evidence: convert(source: [evidence]))
        let vc = try VerifiableCredential.create(options: options)
        let vcJwt = try await vc.sign(did: issuerDid)
        try await VerifiableCredential.verify(jwt: vcJwt)
        let parsedVC = try VerifiableCredential.parse(jwt: vcJwt)

        for currentVC in [vc, parsedVC] {
            XCTAssertEqual(currentVC.issuer(), issuerDid.did.uri)
            XCTAssertEqual(currentVC.subject(), issuerDid.did.uri)
            XCTAssertEqual(currentVC.type(), "TBDeveloperCredential")
            XCTAssertNotNil(currentVC.vcDataModel.issuanceDate)
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["id"]?.value as! String, issuerDid.did.uri)
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["name"]?.value as! String, "bob")
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["role"]?.value as! String, "test engineer")
            XCTAssertEqual(vc.vcDataModel.evidence?.first?["id"]?.value as! String, evidence.id)
            XCTAssertEqual(vc.vcDataModel.evidence?.first?["type"]?.value as! [String], evidence.type)
            XCTAssertEqual(vc.vcDataModel.evidence?.first?["verifier"]?.value as! String, evidence.verifier)
            XCTAssertEqual(vc.vcDataModel.evidence?.first?["evidenceDocument"]?.value as! String, evidence.evidenceDocument)
            XCTAssertEqual(vc.vcDataModel.evidence?.first?["subjectPresence"]?.value as! String, evidence.subjectPresence)
            XCTAssertEqual(vc.vcDataModel.evidence?.first?["documentPresence"]?.value as! String, evidence.documentPresence)
        }
    }

    func test_throwErrorIfWrongIssuer() async throws {
        
        let issuer1 = try! DIDJWK.create();
        let issuer2 = try! DIDJWK.create();
        let options = VCCOptions(type: ["TBDeveloperCredential"], 
                                 issuer: issuer1.did.uri, 
                                 subject: "did:subject:123",
                                 data: convert(source: [TBDeveloper(name: "bob", role: "test engineer")]).first!)

        let vc = try VerifiableCredential.create(options: options)
        let vcJwt = try await vc.sign(did: issuer2)
        do {
            try await VerifiableCredential.verify(jwt: vcJwt)
        } catch let err {
            XCTAssertEqual(err as! VerifiableCredential.Error, VerifiableCredential.Error.verificationFailed("iss claim does not match expected issuer"))
        }

    }
}