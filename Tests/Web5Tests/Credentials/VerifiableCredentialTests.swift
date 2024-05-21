import XCTest
import AnyCodable
@testable import Web5

class VerifiableCredentialTests: XCTestCase {

    var issuerDid: BearerDID?

    override func setUp() {
        issuerDid = try! DIDJWK.create();
    }
    
    struct VCCOptions: VerifiableCredentialCreateOptions {
        var type: [String]
        var issuer: String
        var subject: String
        var data: [String: AnyCodable]?
        var issuanceDate: ISO8601Date?
        var expirationDate: ISO8601Date?
        var evidence: [String: AnyCodable]?
    }

    func convertFrom(source: Any) -> [String: AnyCodable] {
        let mirror = Mirror(reflecting: source)
        var dictionary = [String: AnyCodable]()
        
        for case let (label?, value) in mirror.children {
            dictionary[label] = AnyCodable(value)
        }
        
        return dictionary
    }

    func test_CreateVC() throws {
        
        struct StreetCredibility {
            let localRespect: String
            let legit: Bool
        }

        let sc = StreetCredibility(localRespect: "high", legit: true)
        let options = VCCOptions(type: ["StreetCred"], 
                                 issuer: issuerDid!.did.uri, 
                                 subject: issuerDid!.did.uri,
                                 data: convertFrom(source: sc))

        let vc = try VerifiableCredential.create(options: options)

        XCTAssertEqual(vc.issuer(), issuerDid!.did.uri)
        XCTAssertEqual(vc.subject(), issuerDid!.did.uri)
        XCTAssertEqual(vc.type(), "StreetCred")
        XCTAssertNotNil(vc.vcDataModel.issuanceDate)
        XCTAssertEqual(vc.vcDataModel.credentialSubject["id"]?.value as! String, issuerDid!.did.uri)
        XCTAssertEqual(vc.vcDataModel.credentialSubject["localRespect"]?.value as! String, "high")
        XCTAssertEqual(vc.vcDataModel.credentialSubject["legit"]?.value as! Bool, true)

    }

    func test_createAndSignVCWithDIDJWk() async throws {
        struct TBDeveloper {
            let name: String
            let role: String
        }
        let options = VCCOptions(type: ["TBDeveloperCredential"], 
                                 issuer: issuerDid!.did.uri, 
                                 subject: issuerDid!.did.uri,
                                 data: convertFrom(source: TBDeveloper(name: "alice", role: "software engineer")))
        let vc = try VerifiableCredential.create(options: options)
        let vcJwt = try await vc.sign(did: issuerDid!)
        try await VerifiableCredential.verify(jwt: vcJwt)
        let parsedVC = try VerifiableCredential.parse(jwt: vcJwt)
        for currentVC in [vc, parsedVC] {
            XCTAssertEqual(currentVC.issuer(), issuerDid!.did.uri)
            XCTAssertEqual(currentVC.subject(), issuerDid!.did.uri)
            XCTAssertEqual(currentVC.type(), "TBDeveloperCredential")
            XCTAssertNotNil(currentVC.vcDataModel.issuanceDate)
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["id"]?.value as! String, issuerDid!.did.uri)
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["name"]?.value as! String, "alice")
            XCTAssertEqual(currentVC.vcDataModel.credentialSubject["role"]?.value as! String, "software engineer")
        }
    }
}