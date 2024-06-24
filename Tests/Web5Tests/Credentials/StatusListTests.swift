import XCTest
import AnyCodable
@testable import Web5

class StatusListTests: XCTestCase {
    
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

    let issuerDid = try! DIDJWK.create();
    let holderDid = try! DIDJWK.create();

    private func exampleCredentialStatus(for index: String) -> StatusList2021Entry {
        let credentialStatus = StatusList2021Entry(id: "cred-with-status-id",
                                                                        type: "StatusList2021Entry",  
                                                                        statusPurpose: "revocation",
                                                                        statusListIndex: index,
                                                                        statusListCredential: "https://example.com/credentials/status/3")
        return credentialStatus
    }

    private func exampleVccOption(with credentialStatus: StatusList2021Entry) -> VCCOptions {
        let data = TBDeveloper(name: "Alice", isRemote: false)
        let vcc = VCCOptions(type: ["TBDeveloperCred"], 
                             issuer: issuerDid.did.uri, 
                             subject: holderDid.did.uri,
                             data: convert(source: [data]).first!,
                             credentialStatus: credentialStatus) 
        return vcc
    }

    private func exampleVerifiableCredential(with index: String) -> VerifiableCredential {
        let credentialStatus = exampleCredentialStatus(for: index)
        let vcc = exampleVccOption(with: credentialStatus)                    
        let credWithCredStatus = try! VerifiableCredential.create(options: vcc)
        return credWithCredStatus
    }

    func test_createStatusList() async throws {
        
        let credentialStatus = exampleCredentialStatus(for: "94567")
        let vcc = exampleVccOption(with: credentialStatus)                    
        let credWithCredStatus = try VerifiableCredential.create(options: vcc)
        let credWithCredStatusContext = credWithCredStatus.vcDataModel.context

        XCTAssertTrue(credWithCredStatusContext.contains("https://w3id.org/vc/status-list/2021/v1"))
        XCTAssertTrue(credWithCredStatusContext.contains("https://www.w3.org/2018/credentials/v1"))
        XCTAssertEqual(credWithCredStatus.vcDataModel.credentialStatus!, credentialStatus)

        let statusListCredOptions = StatusListCredentialCreateOptions(statusListCredentialId: "https://statuslistcred.com/123",
                                                                                                        issuer: issuerDid.did.uri,
                                                                                                        statusPurpose: StatusPurpose.revocation,
                                                                                                        credentialsToDisable: [credWithCredStatus])
        let statusListCred = try StatusListCredential.create(options: statusListCredOptions) 
        let statusListCredContext = statusListCred.vcDataModel.context

        XCTAssertEqual(statusListCred.vcDataModel.id, "https://statuslistcred.com/123")
        XCTAssertTrue(statusListCredContext.contains("https://w3id.org/vc/status-list/2021/v1"))
        XCTAssertTrue(statusListCredContext.contains("https://www.w3.org/2018/credentials/v1"))
        XCTAssertEqual(statusListCred.type(), "StatusList2021Credential")
        XCTAssertEqual(statusListCred.issuer(), issuerDid.did.uri)

        let statusListCredSubject = statusListCred.vcDataModel.credentialSubject
        XCTAssertEqual(statusListCredSubject["id"]?.value as! String, "https://statuslistcred.com/123")
        XCTAssertEqual(statusListCredSubject["type"]?.value as! String, "StatusList2021")
        XCTAssertEqual(statusListCredSubject["statusPurpose"]?.value as! StatusPurpose, StatusPurpose.revocation)
        XCTAssertEqual(statusListCredSubject["encodedList"]?.value as! String, "H4sIAAAAAAAAE-3OMQ0AAAgDsOHfNBp2kZBWQRMAAAAAAAAAAAAAAL6Z6wAAAAAAtQVQdb5gAEAAAA")
    }

    // TODO: Check encoding across other sdks and spec - https://github.com/TBD54566975/web5-kt/issues/52  
    func test_encodedListAcrossSDKs() async throws {
        let javascriptEncodedList = "H4sIAAAAAAAAA-3OMQ0AAAgDsOHfNBp2kZBWQRMAAAAAAAAAAAAAAL6Z6wAAAAAAtQVQdb5gAEAAAA"
        let swiftEncodedList      = "H4sIAAAAAAAAE-3OMQ0AAAgDsOHfNBp2kZBWQRMAAAAAAAAAAAAAAL6Z6wAAAAAAtQVQdb5gAEAAAA"
        let js_bit = try StatusListCredential.getBit(s: javascriptEncodedList, i: 94567)
        let swift_bit = try StatusListCredential.getBit(s: swiftEncodedList, i: 94567)
        XCTAssertTrue(js_bit)
        XCTAssertTrue(swift_bit)
    }

    func test_multipleRevokedVerifiableCredentials() async throws {

        let vc1 = exampleVerifiableCredential(with: "123")
        let vc2 = exampleVerifiableCredential(with: "124")
        let vc3 = exampleVerifiableCredential(with: "1247")

        let statusListCredOptions = StatusListCredentialCreateOptions(statusListCredentialId: "revocation-id",
                                                                      issuer: issuerDid.did.uri,
                                                                      statusPurpose: StatusPurpose.revocation,
                                                                      credentialsToDisable: [vc1, vc2])
        let statusListCredential = try StatusListCredential.create(options: statusListCredOptions) 
        
        XCTAssertNotNil(statusListCredential)
        XCTAssertEqual(statusListCredential.subject(), "revocation-id")

        let statusListCredentialSubject = statusListCredential.vcDataModel.credentialSubject
        XCTAssertEqual(statusListCredentialSubject["type"]?.value as! String, "StatusList2021")
        XCTAssertEqual(statusListCredentialSubject["statusPurpose"]?.value as! StatusPurpose, StatusPurpose.revocation)

        XCTAssertTrue(try! StatusListCredential.validateCredentialInStatusList(credentialToValidate: vc1, statusListCredential: statusListCredential))
        XCTAssertTrue(try! StatusListCredential.validateCredentialInStatusList(credentialToValidate: vc2, statusListCredential: statusListCredential))
        XCTAssertFalse(try! StatusListCredential.validateCredentialInStatusList(credentialToValidate: vc3, statusListCredential: statusListCredential))
    }

    func test_duplicatedIndex() async throws {
        let vc = exampleVerifiableCredential(with: "94567")
        let statusListCredOptions = StatusListCredentialCreateOptions(statusListCredentialId: "revocation-id",
                                                                      issuer: issuerDid.did.uri,
                                                                      statusPurpose: StatusPurpose.revocation,
                                                                      credentialsToDisable: [vc, vc])
        do {
            _ = try StatusListCredential.create(options: statusListCredOptions)
            XCTFail("should have produced duplicated index error")
        } catch let error {
            let err = error as! StatusListCredential.Error
            XCTAssertEqual(err, StatusListCredential.Error.statusListCredentialError("Duplicate entry found with index: 94567"))
        }
        
    }

    func test_negativeIndex() async throws {
        let vc = exampleVerifiableCredential(with: "-3")
        let statusListCredOptions = StatusListCredentialCreateOptions(statusListCredentialId: "revocation-id",
                                                                      issuer: issuerDid.did.uri,
                                                                      statusPurpose: StatusPurpose.revocation,
                                                                      credentialsToDisable: [vc])
        do {
            _ = try StatusListCredential.create(options: statusListCredOptions)
            XCTFail("should have produced negative index error")
        } catch let error {
            let err = error as! StatusListCredential.Error
            XCTAssertEqual(err, StatusListCredential.Error.statusListCredentialError("Status list index cannot be negative"))
        }
        
    }

    func test_largerThanMaximumSizeIndex() async throws {
        let vc = exampleVerifiableCredential(with: String(Int.max))
        let statusListCredOptions = StatusListCredentialCreateOptions(statusListCredentialId: "revocation-id",
                                                                      issuer: issuerDid.did.uri,
                                                                      statusPurpose: StatusPurpose.revocation,
                                                                      credentialsToDisable: [vc])
        do {
            _ = try StatusListCredential.create(options: statusListCredOptions)
            XCTFail("should have produced larger than the bitset size index error")
        } catch let error {
            let err = error as! StatusListCredential.Error
            XCTAssertEqual(err, StatusListCredential.Error.statusListCredentialError("Status list index is larger than the bitset size"))
        }
        
    }
}