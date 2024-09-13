import XCTest

@testable import Web5

class VP1BVerifierTests: XCTestCase {

    var jsonDecoder: JSONDecoder!

    override func setUp() {
        super.setUp()

        jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .iso8601
    }

    func testVerifyQRCode_ValidQRCode() throws {
        let qrCodeText = "VP1-B3ECQDIYACEMHIGDODB6KQAMDCELBIGDQQIBVBIRXWSRP46SGK63XJ4WBTA2XR5QYOKSRQ5AYSYMLMGTGY5A7MGF6DDCBRQCYIF5HRINVLSSGYN7DAQKLPG7OJZFQOMV6SPRNMCVVAPPLTJXIF5KKO5L4EVW6QIHTWXATK2OPGURQ5XDXBS5HEYKBOQBNIC5NRG64E5GKBAMMFAYZAQAVQIXNAHRBLZWZVHXBYO6AKQARBE6FTCCQBZEZIQ67FYTDR4OJFBCHEMBN6WBC5UA6EFPG3GU64HB3YBKACEETYWMIKAHETFCD34XCMOHRZEUEI4RQFXYYOWBBQ3AYQIMJ5IQYRJMFO6WZAUA2IAAVDBVBQZAYNRFHVWIFAGRAAFQYPQKRQ3SYHN5AAAOABTBGZWGPOB3BUTVEFS4U6CXMVFSGVZDD7STZCEQC4BHZQJ2NGFVEUI3TYEGFT4D66QQ4GQIAMLT6WHG6ZVZKXB4FDCKBKGFCDJUAHKPUDCSBUZWHIH3BRKECDECACWBC5UA6EFPG3GU64HB3YBKACEETYWMIKAHETFCD34XCMOHRZEUEI4RQFXY"

        let vp1b = try VP1BVerifier.verifyQRCode(qrcode: qrCodeText)

        XCTAssertNotNil(vp1b.credential, "The credential should not be nil.")
        XCTAssertEqual(vp1b.credential.id, "urn:uuid:a237b4a2-fe7a-4657-b774-f2c1983578f6")
        XCTAssertEqual(vp1b.credential.issuer, "did:key:z6MkufoZ9wqtydKCPiZ5PAZ1MhLgmvXnjGUwbhhzQdAfnysc")
        XCTAssertEqual(vp1b.credential.subject.overAge, 21)
        XCTAssertEqual(vp1b.credential.proof.method, "did:key:z6MkufoZ9wqtydKCPiZ5PAZ1MhLgmvXnjGUwbhhzQdAfnysc#z6MkufoZ9wqtydKCPiZ5PAZ1MhLgmvXnjGUwbhhzQdAfnysc")
    }

    func testVerifyIssuer_ValidIssuer() async throws {
        let json = """
        {
          "credential": {
            "id": "urn:uuid:a89b7ec5-41ad-4c0c-b776-31a45f5a671b",
            "issuance": "2024-08-22T13:49:40Z",
            "expiration": "2025-04-19T13:49:40Z",
            "issuer": "did:key:z6MkufoZ9wqtydKCPiZ5PAZ1MhLgmvXnjGUwbhhzQdAfnysc",
            "subject": {
              "concealedIdToken": "z6CUSkPdGvT6AtkHCBDPkAXCPoALA4qionKUv7YufEhgqE5wLeeWvhHcXACjoM1qTaNRfRXTLdDweK2E9TAb1rzH3qKPDFbYbYBYEuYjp3NNwXjXLFxqZqx",
              "overAge": 21
            },
            "proof": {
              "created": "2024-08-22T13:49:41Z",
              "method": "did:key:z6MkufoZ9wqtydKCPiZ5PAZ1MhLgmvXnjGUwbhhzQdAfnysc#z6MkufoZ9wqtydKCPiZ5PAZ1MhLgmvXnjGUwbhhzQdAfnysc",
              "value": "z5cBu74qufm6TweS2wZtg4R464RuHYMAe4CuyNv2QFbsYhvqPADBwWeC261utL7VvhnzxykVyzpRXbm7yjPpifiSu"
            }
          }
        }
        """.data(using: .utf8)!

        do {
            let vp1b = try jsonDecoder.decode(VP1B.self, from: json)

            let vp1bIssuer = try await VP1BVerifier.verifyIssuer(credential: vp1b.credential)

            XCTAssertEqual(vp1bIssuer.id, "did:key:z6MkufoZ9wqtydKCPiZ5PAZ1MhLgmvXnjGUwbhhzQdAfnysc")
            XCTAssertEqual(vp1bIssuer.name, "TruAge Issuer")
            XCTAssertTrue(vp1bIssuer.credentialTypes.contains("OverAgeTokenCredential"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testVerifyIssuer_InvalidIssuer() async throws {
        let json = """
        {
          "credential": {
            "id": "urn:uuid:188e8450-269e-11eb-b545-d3692cf35398",
            "issuance": "2021-03-24T20:03:03Z",
            "expiration": "2021-06-24T20:03:03Z",
            "issuer": "did:key:z6MkkUbCFazdoducKf8SUye7cAxuicMdDBhXKWuTEuGA3jQF",
            "subject": {
              "concealedIdToken": "zo58FV8vqzY2ZqLT4fSaVhe7CsdBKsUikBMbKridqSyc7LceLmgWcNTeHm2gfvgjuNjrVif1G2A5EKx2eyNkSu5ZBc6gNnjF8ZkV3P8dPrX8o46SF",
              "overAge": 21
            },
            "proof": {
              "created": "2021-08-07T21:36:26Z",
              "method": "did:key:z6MkkUbCFazdoducKf8SUye7cAxuicMdDBhXKWuTEuGA3jQF#z6MkkUbCFazdoducKf8SUye7cAxuicMdDBhXKWuTEuGA3jQF",
              "value": "z4mAs9uHU16jR4xwPcbhHyRUc6BbaiJQE5MJwn3PCWkRXsriK9AMrQQMbjzG9XXFPNgngmQXHKUz23WRSu9jSxPCF"
            }
          }
        }
        """.data(using: .utf8)!

        do {
            let vp1b = try jsonDecoder.decode(VP1B.self, from: json)

            _ = try await VP1BVerifier.verifyIssuer(credential: vp1b.credential)

            XCTFail("Expected an invalid issuer error but did not receive one.")
        } catch let error as VP1BIssuers.Error {
            XCTAssertEqual(error, .issuerNotFound, "Expected invalid issuer error.")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}
