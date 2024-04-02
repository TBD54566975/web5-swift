import Foundation
import XCTest
@testable import Web5

final class PortableDIDTests: XCTestCase {

    func test_success_parse() throws {
       let dataModel = try JSONDecoder().decode(PortableDID.self, from: successJson().data(using: .utf8)!); 
       XCTAssertNotNil(dataModel);
    }

    private func successJson() -> String {
        return """
        {
        "uri": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
        "privateKeys": [
          {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": "JQV3CEZCpVZpBZd47A3-ieMC5OPo8ryBT9pwK_sC-KA",
            "d": "8L5Y7M4ZNc9Jy5IooJNFaRGatXHZzRRXxGsVidrAsfE",
            "x": "U3YsC61IfpqF9jPsQ_MT00EM4AAuGbk4H3uUVQs0EzQ"
          }
        ],
        "document": {
          "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
          "verificationMethod": [
            {
              "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ#0",
              "type": "JsonWebKey",
              "controller": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
              "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": "JQV3CEZCpVZpBZd47A3-ieMC5OPo8ryBT9pwK_sC-KA",
                "x": "U3YsC61IfpqF9jPsQ_MT00EM4AAuGbk4H3uUVQs0EzQ"
              }
            }
          ]
        },
        "metadata": {
          "foo": "bar"
        }
        }
        """
    }

    func test_missing_uri_parse() throws {
        do {
            _ = try JSONDecoder().decode(PortableDID.self, from: missingUriJson().data(using: .utf8)!); 
        } catch let error {
            XCTAssertNotNil(error);
        }
    }

    private func missingUriJson() -> String {
        return """
        {
        "privateKeys": [
          {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": "JQV3CEZCpVZpBZd47A3-ieMC5OPo8ryBT9pwK_sC-KA",
            "d": "8L5Y7M4ZNc9Jy5IooJNFaRGatXHZzRRXxGsVidrAsfE",
            "x": "U3YsC61IfpqF9jPsQ_MT00EM4AAuGbk4H3uUVQs0EzQ"
          }
        ],
        "document": {
          "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
          "verificationMethod": [
            {
              "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ#0",
              "type": "JsonWebKey",
              "controller": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
              "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": "JQV3CEZCpVZpBZd47A3-ieMC5OPo8ryBT9pwK_sC-KA",
                "x": "U3YsC61IfpqF9jPsQ_MT00EM4AAuGbk4H3uUVQs0EzQ"
              }
            }
          ]
        },
        "metadata": {
          "foo": "bar"
        }
        }
        """
    }

    func test_missing_privatekey() throws {
        do {
            _ = try JSONDecoder().decode(PortableDID.self, from: missingPrivatekeyJson().data(using: .utf8)!); 
        } catch let error {
            XCTAssertNotNil(error);
        }
    }

    private func missingPrivatekeyJson() -> String {
        return """
        {
        "uri": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
        "document": {
          "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
          "verificationMethod": [
            {
              "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ#0",
              "type": "JsonWebKey",
              "controller": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
              "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": "JQV3CEZCpVZpBZd47A3-ieMC5OPo8ryBT9pwK_sC-KA",
                "x": "U3YsC61IfpqF9jPsQ_MT00EM4AAuGbk4H3uUVQs0EzQ"
              }
            }
          ]
        },
        "metadata": {
          "foo": "bar"
        }
        }
        """
    }

    func test_missing_document() throws {
        do {
            _ = try JSONDecoder().decode(PortableDID.self, from: missingDocumentJson().data(using: .utf8)!); 
        } catch let error {
            XCTAssertNotNil(error);
        }
    }

    private func missingDocumentJson() -> String {
        return """
        {
        "uri": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
        "privateKeys": [
          {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": "JQV3CEZCpVZpBZd47A3-ieMC5OPo8ryBT9pwK_sC-KA",
            "d": "8L5Y7M4ZNc9Jy5IooJNFaRGatXHZzRRXxGsVidrAsfE",
            "x": "U3YsC61IfpqF9jPsQ_MT00EM4AAuGbk4H3uUVQs0EzQ"
          }
        ],
        "metadata": {
          "foo": "bar"
        }
        }
        """
    }

    func test_missing_metaData() throws {
        do {
            _ = try JSONDecoder().decode(PortableDID.self, from: missingMetadataJson().data(using: .utf8)!); 
        } catch let error {
            XCTAssertNotNil(error);
        }
    }


    private func missingMetadataJson() -> String {
        return """
        {
        "uri": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
        "privateKeys": [
          {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": "JQV3CEZCpVZpBZd47A3-ieMC5OPo8ryBT9pwK_sC-KA",
            "d": "8L5Y7M4ZNc9Jy5IooJNFaRGatXHZzRRXxGsVidrAsfE",
            "x": "U3YsC61IfpqF9jPsQ_MT00EM4AAuGbk4H3uUVQs0EzQ"
          }
        ],
        "document": {
          "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
          "verificationMethod": [
            {
              "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ#0",
              "type": "JsonWebKey",
              "controller": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwiYWxnIjoiRWREU0EiLCJraWQiOiJKUVYzQ0VaQ3BWWnBCWmQ0N0EzLWllTUM1T1BvOHJ5QlQ5cHdLX3NDLUtBIiwieCI6IlUzWXNDNjFJZnBxRjlqUHNRX01UMDBFTTRBQXVHYms0SDN1VVZRczBFelEifQ",
              "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": "JQV3CEZCpVZpBZd47A3-ieMC5OPo8ryBT9pwK_sC-KA",
                "x": "U3YsC61IfpqF9jPsQ_MT00EM4AAuGbk4H3uUVQs0EzQ"
              }
            }
          ]
        }
        }
        """
    }
}