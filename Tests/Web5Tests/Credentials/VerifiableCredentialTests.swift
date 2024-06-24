import XCTest
import AnyCodable
@testable import Web5

class VerifiableCredentialTests: XCTestCase {
    private struct TBDeveloper {
        let name: String
        let isRemote: Bool
    }

    private struct VCCOptions: VerifiableCredentialCreateOptions {
        var type: [String]
        var issuer: String
        var subject: String
        var issuanceDate: ISO8601Date?
        var expirationDate: ISO8601Date?
        var data: [String: AnyCodable]?
        var credentialStatus: StatusList2021Entry?
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

    private func validVCCOptions(didUri: String) -> VCCOptions {
        let options = VCCOptions(type: ["TBDeveloperCredential"], 
                                 issuer: didUri, 
                                 subject: didUri,
                                 data: convert(source: [TBDeveloper(name: "alice", isRemote: true)]).first!)
        return options
    }

    func test_CreateVC() throws {
        
        let issuerDid = try! DIDJWK.create();
        let vc = try VerifiableCredential.create(options: validVCCOptions(didUri: issuerDid.did.uri))

        XCTAssertEqual(vc.issuer(), issuerDid.did.uri)
        XCTAssertEqual(vc.subject(), issuerDid.did.uri)
        XCTAssertEqual(vc.type(), "TBDeveloperCredential")
        XCTAssertNotNil(vc.vcDataModel.issuanceDate)
        XCTAssertEqual(vc.vcDataModel.credentialSubject["id"]?.value as! String, issuerDid.did.uri)
        XCTAssertEqual(vc.vcDataModel.credentialSubject["name"]?.value as! String, "alice")
        XCTAssertEqual(vc.vcDataModel.credentialSubject["isRemote"]?.value as! Bool, true)

    }

    func test_createAndSignVCWithDidJWk() async throws {
        let issuerDid = try! DIDJWK.create();
        let vc = try VerifiableCredential.create(options: validVCCOptions(didUri: issuerDid.did.uri))
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
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["isRemote"]?.value as! Bool, true)
        }
        XCTAssertEqual(vc, parsedVC)
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
        var options = validVCCOptions(didUri: issuerDid.did.uri)
        options.evidence = convert(source: [evidence])
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
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["isRemote"]?.value as! Bool, true)
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
        let vc = try VerifiableCredential.create(options: validVCCOptions(didUri: issuer1.did.uri))
        let vcJwt = try await vc.sign(did: issuer2)
        do {
            try await VerifiableCredential.verify(jwt: vcJwt)
        } catch let err {
            XCTAssertEqual(err as! VerifiableCredential.Error, VerifiableCredential.Error.verificationFailed("iss claim does not match expected issuer"))
        }

    }

    func test_throwIfIssuerOrSubjectUndefined() async throws {
        let issuerDid = "did:example:issuer"
        let subjectDid = "did:example:subject"
        var options = validVCCOptions(didUri: subjectDid)
        options.issuer = ""
        do {
            _ = try VerifiableCredential.create(options: options)
        } catch let err {
            XCTAssertEqual(err as! VerifiableCredential.Error, VerifiableCredential.Error.verificationFailed("Issuer and subject must be defined"))
        }

        options.issuer = issuerDid
        options.subject = ""
        do {
            _ = try VerifiableCredential.create(options: options)
        } catch let err {
            XCTAssertEqual(err as! VerifiableCredential.Error, VerifiableCredential.Error.verificationFailed("Issuer and subject must be defined"))
        }
    }

    func test_signEd25519KeyWorks() async throws {
        let issuerDid = try! DIDJWK.create();
        let vc = try VerifiableCredential.create(options: validVCCOptions(didUri: issuerDid.did.uri))
        let vcJwt = try await vc.sign(did: issuerDid)
        XCTAssertNotNil(vcJwt)
        let parts = vcJwt.split(separator: ".")
        XCTAssertTrue(parts.count == 3)
    }

    func test_signSecp256k1KeyWorks() async throws {
        let issuerDid = try! DIDJWK.create(options: DIDJWK.CreateOptions(algorithm: .secp256k1));
        let vc = try VerifiableCredential.create(options: validVCCOptions(didUri: issuerDid.did.uri))
        let vcJwt = try await vc.sign(did: issuerDid)
        XCTAssertNotNil(vcJwt)
        let parts = vcJwt.split(separator: ".")
        XCTAssertTrue(parts.count == 3)
    }

    func test_throwIfInvalidJwt() async throws {
        do {
            _ = try VerifiableCredential.parse(jwt: "Hi")
        } catch let error {
            XCTAssertEqual(error as! JWT.Error, JWT.Error.verificationFailed("Malformed JWT. Expected 3 parts. Got 1"))
        }
    }

    func test_throwIfParseJwtMissingVCProperty() async throws {
        let did = try! DIDJWK.create();
        let jwt = try JWT.sign(did: did, claims: JWT.Claims(issuer: did.did.uri, subject: did.did.uri))
        do {
            _ = try VerifiableCredential.parse(jwt: jwt)
        } catch let error {
            XCTAssertEqual(VerifiableCredential.Error.verificationFailed("Expected vc in JWT payload"), error as! VerifiableCredential.Error)
        }
    }

    func test_parseJwtSuccessReturnsVC() async throws {
        let issuerDid = try! DIDJWK.create();
        let vc = try VerifiableCredential.create(options: validVCCOptions(didUri: issuerDid.did.uri))
        let vcJwt = try await vc.sign(did: issuerDid)
        let parsedVC = try VerifiableCredential.parse(jwt: vcJwt)
        XCTAssertNotNil(parsedVC)
        XCTAssertEqual(parsedVC.issuer(), vc.issuer())
        XCTAssertEqual(parsedVC.subject(), vc.subject())
        XCTAssertEqual(parsedVC.type(), vc.type())
    }

    func test_failsToVerifyInvalidVCJwt() async throws {
        do {
            _ = try VerifiableCredential.parse(jwt: "invalid-jwt")
        } catch let error {
            XCTAssertEqual(JWT.Error.verificationFailed("Malformed JWT. Expected 3 parts. Got 1"), error as! JWT.Error)
        }
    }

    func test_throwIfAlgNotSupport() async throws {
        let invalidJwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        do {
            _ = try VerifiableCredential.parse(jwt: invalidJwt)
        } catch let error {
            //This is swift decoding error. Does not support HS256
            XCTAssertNotNil(error)
        }
    }

    func test_verifyDoesNotThrowWithValidVC() async throws {
        let issuerDid = try! DIDJWK.create();
        let vc = try VerifiableCredential.create(options: validVCCOptions(didUri: issuerDid.did.uri))
        let vcJwt = try await vc.sign(did: issuerDid)

        let expectation = expectation(description: "VerifiableCredential should verify successfully")

        do {
            try await VerifiableCredential.verify(jwt: vcJwt)
            expectation.fulfill()
        } catch let error {
            XCTFail("VerifiableCredential should have verified successfully. Unexpected error: \(error)")
        }
        await fulfillment(of: [expectation], timeout: 5.0, enforceOrder: true)
    }
}