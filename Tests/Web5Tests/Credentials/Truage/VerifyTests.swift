import XCTest

@testable import Web5

class VerifyTests: XCTestCase {
    
    func testVerifyQrCodeText_ValidQRCode() throws {
        let validQRCodeText = "VP1-B3ECQDIYACEMHIGDODB6KQAMDCELBIGDQQIBVAADIXHBIQX2PFCEVATORHCCS2LYYOKSRQ5AYSYMLMGTEEHEVWGF6DDCBRQCYIF5DCQDI3YNUWHN53SMBYY75SQPJQUBD73YL5OH3DDLALMINCE55XRFBEUS2SCJY52BAXJE3TKYA6I6SSVHDX4CF4LWYVZFDXPMQ536WBAMMFAYZAQAVQIXNAFIOG5RWAVVT5UYU32LAGAUXMSXZUJL3GLMGCMPGWKFOWUNW44G66WBC5UAVBY3WGYCWWPWTCTPJMAYCS5SK7GRFPMZNQYJR42ZIV22RW3TQ33YYOWBBQ3AYQIMJ5IQYRJMFO6WZAUA2IAAVDBVBQZAYNRFHVWIFAGRAAFQYPQKRQ3SYHN5AAAKG3JGL6G7AC3LL7YEC7KLUV7BHOTPEOYX6P53HWMLQH42P4XYY6YY3U53CG7OG7XUBKMZU6B7DTQ2GNJKDME26GUGADCKBKGFCDJSV4LGSDCSBUZBBZFNRRKECDECACWBC5UAVBY3WGYCWWPWTCTPJMAYCS5SK7GRFPMZNQYJR42ZIV22RW3TQ33Y"
        
        let verificationResult = try verifyQrCodeText(qrCodeText: validQRCodeText)
        
        XCTAssertTrue(verificationResult.verified, "The QR code should be verified successfully.")
        XCTAssertNotNil(verificationResult.credential, "The credential should not be nil.")
        XCTAssertNotNil(verificationResult.issuer, "The issuer should not be nil.")
        XCTAssertNotNil(verificationResult.overAge, "The overAge field should not be nil.")
    }
    
    func testVerifyQrCodeText_InvalidQRCode() throws {
        let invalidQRCodeText = "VP1-BINVALID..." // Replace with an invalid encoded QR code text
        
        let verificationResult = try verifyQrCodeText(qrCodeText: invalidQRCodeText)
        
        XCTAssertFalse(verificationResult.verified, "The QR code should not be verified.")
//        XCTAssertNotNil(verificationResult.error, "There should be an error during verification.")
    }
    
    func testVerifyQrCodeText_MissingCredential() throws {
        let missingCredentialQRCodeText = "VP1-B..." // Replace with a QR code that is missing the credential
        
        let verificationResult = try verifyQrCodeText(qrCodeText: missingCredentialQRCodeText)
        
        XCTAssertFalse(verificationResult.verified, "The QR code should not be verified.")
//        XCTAssertNotNil(verificationResult.error, "There should be an error due to missing credential.")
    }
    
    // Example of a test case for verifying a QR code with an overAge mismatch
    func testVerifyQrCodeText_OverAgeMismatch() throws {
        let overAgeMismatchQRCodeText = "VP1-B..." // Replace with a QR code that has an overAge mismatch
        
        let verificationResult = try verifyQrCodeText(qrCodeText: overAgeMismatchQRCodeText)
        
        XCTAssertFalse(verificationResult.verified, "The QR code should not be verified due to overAge mismatch.")
//        XCTAssertNotNil(verificationResult.error, "There should be an error due to overAge mismatch.")
    }
}
