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
}