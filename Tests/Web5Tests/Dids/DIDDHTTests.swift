import Mocker
import XCTest

@testable import Web5

final class DIDDHTTests: XCTestCase {

    func test_resolve_publishedDID_withSingleVerificationMethod() async throws {
        Mock(
            url: URL(string: "https://diddht.tbddev.org/pjiiw7ibn6t9k1mkknkowjketa8chksgwzkt5uk8798epux1386o")!,
            statusCode: 200,
            data: [
                .get: Data.fromHexString(
                    """
                    5f011403ca8a3dbf0935a4f598b47c965b66bc67c86c7b665fbbfa6a31013075f512bbf68ca5\
                    c1b6f6ddde45b6645366a7234e204ae6f7c2d0bf4b9b99efae050000000065b0123100008400\
                    0000000200000000035f6b30045f64696434706a6969773769626e3674396b316d6b6b6e6b6f\
                    776a6b6574613863686b7367777a6b7435756b3837393865707578313338366f000010000100\
                    001c2000373669643d303b743d303b6b3d616d7461647145586f5f564a616c4356436956496a\
                    67374f4b73616c3152334e522d5f4f68733379796630045f64696434706a6969773769626e36\
                    74396b316d6b6b6e6b6f776a6b6574613863686b7367777a6b7435756b383739386570757831\
                    3338366f000010000100001c20002726763d303b766d3d6b303b617574683d6b303b61736d3d\
                    6b303b64656c3d6b303b696e763d6b30
                    """
                )!
            ]
        ).register()

        let didURI = "did:dht:pjiiw7ibn6t9k1mkknkowjketa8chksgwzkt5uk8798epux1386o"
        let didResolutionResult = await DIDDHT.Resolver().resolve(didURI: didURI)

        XCTAssertNotNil(didResolutionResult.didDocument)
        XCTAssertNotNil(didResolutionResult.didDocumentMetadata)
        XCTAssertNotNil(didResolutionResult.didResolutionMetadata)

        XCTAssertEqual(didResolutionResult.didDocument?.id, didURI)
        XCTAssertEqual(didResolutionResult.didDocument?.verificationMethod?.count, 1)
    }

    func test_resolve_publishedDID_withServices() async throws {
        Mock(
            url: URL(string: "https://diddht.tbddev.org/1wiaaaoagzceggsnwfzmx5cweog5msg4u536mby8sqy3mkp3wyko")!,
            statusCode: 200,
            data: [
                .get: Data.fromHexString(
                    """
                    19c356a57605e7be8d101e211137dec2bbb875f076a60866529eff68372380c63e435c852bf3\
                    dbc6fa4bbda014c561af361cace90c91350477c010769a9910060000000065b035ce00008400\
                    0000000300000000035f6b30045f646964343177696161616f61677a63656767736e77667a6d\
                    78356377656f67356d736734753533366d627938737179336d6b703377796b6f000010000100\
                    001c2000373669643d303b743d303b6b3d6c53754d5968673132494d6177714675742d325552\
                    413231324e7165382d574542374f426c616d356f4255035f7330045f64696434317769616161\
                    6f61677a63656767736e77667a6d78356377656f67356d736734753533366d62793873717933\
                    6d6b703377796b6f000010000100001c2000393869643d64776e3b743d446563656e7472616c\
                    697a65645765624e6f64653b73653d68747470733a2f2f6578616d706c652e636f6d2f64776e\
                    045f646964343177696161616f61677a63656767736e77667a6d78356377656f67356d736734\
                    753533366d627938737179336d6b703377796b6f000010000100001c20002e2d763d303b766d\
                    3d6b303b617574683d6b303b61736d3d6b303b64656c3d6b303b696e763d6b303b7376633d73\
                    30
                    """
                )!
            ]
        ).register()

        let didURI = "did:dht:1wiaaaoagzceggsnwfzmx5cweog5msg4u536mby8sqy3mkp3wyko"
        let didResolutionResult = await DIDDHT.Resolver().resolve(didURI: didURI)

        XCTAssertEqual(didResolutionResult.didDocument?.service?.count, 1)
        XCTAssertEqual(didResolutionResult.didDocument?.service?.first?.id, "\(didURI)#dwn")
    }

    func test_resolve_publishedDID_withController() async throws {
        Mock(
            url: URL(string: "https://diddht.tbddev.org/f4d6bg3c1gjshqo1ek3d954z3my1oehon1tkjhc6j4f5m6fdh94o")!,
            statusCode: 200,
            data: [
                .get: Data.fromHexString(
                    """
                    980110156ea686d159d62952c43a151e9fc8f69d9edf0ed38ae78505a3a340f4508de2adad29\
                    342e4acf9f3149b976234c6157272b28937e9b217a03e5a66e0f0000000065b0f2db00008400\
                    0000000300000000045f636e740364696434663464366267336331676a7368716f31656b3364\
                    3935347a336d79316f65686f6e31746b6a6863366a3466356d3666646839346f000010000100\
                    001c200011106469643a6578616d706c653a31323334035f6b30045f64696434663464366267\
                    336331676a7368716f31656b33643935347a336d79316f65686f6e31746b6a6863366a346635\
                    6d3666646839346f000010000100001c2000373669643d303b743d303b6b3d4c6f66676d7979\
                    526b323436456b4b79502d39587973456f493541556f7154786e6b364c7466696a355f55045f\
                    64696434663464366267336331676a7368716f31656b33643935347a336d79316f65686f6e31\
                    746b6a6863366a3466356d3666646839346f000010000100001c20002726763d303b766d3d6b\
                    303b617574683d6b303b61736d3d6b303b64656c3d6b303b696e763d6b30
                    """
                )!
            ]
        ).register()

        let didURI = "did:dht:f4d6bg3c1gjshqo1ek3d954z3my1oehon1tkjhc6j4f5m6fdh94o"
        let didResolutionResult = await DIDDHT.Resolver().resolve(didURI: didURI)

        XCTAssertNotNil(didResolutionResult.didDocument?.controller)
    }

    func test_resolve_publishedDID_withAlsoKnownAsIdentifier() async throws {
        Mock(
            url: URL(string: "https://diddht.tbddev.org/knf5n7q5hfnez5kcmm49g4knqj5mrra9773rfunswo5xtrieoqmo")!,
            statusCode: 200,
            data: [
                .get: Data.fromHexString(
                    """
                    802d44499e456cdee25fef5ffe6f6fbc56201be836d8d44bcb1332a6414529a5503e514230e0\
                    d0ec63a33d12a79aa06c3b8212160f514e40c9ac1b0f479128040000000065b0f37c00008400\
                    0000000300000000045f616b6103646964346b6e66356e37713568666e657a356b636d6d3439\
                    67346b6e716a356d727261393737337266756e73776f3578747269656f716d6f000010000100\
                    001c200011106469643a6578616d706c653a31323334035f6b30045f646964346b6e66356e37\
                    713568666e657a356b636d6d343967346b6e716a356d727261393737337266756e73776f3578\
                    747269656f716d6f000010000100001c2000373669643d303b743d303b6b3d55497578646476\
                    68524976745446723138326c43636e617945785f76636b4c4d567151322d4a4b6f673563045f\
                    646964346b6e66356e37713568666e657a356b636d6d343967346b6e716a356d727261393737\
                    337266756e73776f3578747269656f716d6f000010000100001c20002726763d303b766d3d6b\
                    303b617574683d6b303b61736d3d6b303b64656c3d6b303b696e763d6b30
                    """
                )!
            ]
        ).register()

        let didURI = "did:dht:knf5n7q5hfnez5kcmm49g4knqj5mrra9773rfunswo5xtrieoqmo"
        let didResolutionResult = await DIDDHT.Resolver().resolve(didURI: didURI)

        XCTAssertNotNil(didResolutionResult.didDocument?.alsoKnownAs)
    }

    func test_resolve_publishedDID_withTypes() async throws {
        Mock(
            url: URL(string: "https://diddht.tbddev.org/9tjoow45ef1hksoo96bmzkwwy3mhme95d7fsi3ezjyjghmp75qyo")!,
            statusCode: 200,
            data: [
                .get: Data.fromHexString(
                    """
                    ea33e704f3a48a3392f54b28744cdfb4e24780699f92ba7df62fd486d2a2cda3f263e1c6bcbd\
                    75d438be7316e5d6e94b13e98151f599cfecefad0b37432bd90a0000000065b0ed1600008400\
                    0000000300000000035f6b30045f6469643439746a6f6f773435656631686b736f6f3936626d\
                    7a6b777779336d686d653935643766736933657a6a796a67686d70373571796f000010000100\
                    001c2000373669643d303b743d303b6b3d5f464d49553174425a63566145502d437536715542\
                    6c66466f5f73665332726c4630675362693239323445045f747970045f6469643439746a6f6f\
                    773435656631686b736f6f3936626d7a6b777779336d686d653935643766736933657a6a796a\
                    67686d70373571796f000010000100001c2000070669643d372c36045f6469643439746a6f6f\
                    773435656631686b736f6f3936626d7a6b777779336d686d653935643766736933657a6a796a\
                    67686d70373571796f000010000100001c20002726763d303b766d3d6b303b617574683d6b30\
                    3b61736d3d6b303b64656c3d6b303b696e763d6b30
                    """
                )!
            ]
        ).register()

        let did = "did:dht:9tjoow45ef1hksoo96bmzkwwy3mhme95d7fsi3ezjyjghmp75qyo"
        let didResolutionResult = await DIDDHT.Resolver().resolve(didURI: did)

        let types = didResolutionResult.didDocumentMetadata.types
        XCTAssertNotNil(types)
        XCTAssertEqual(types?.count, 2)
        XCTAssert(types?.contains { $0 == 6 } ?? false)
        XCTAssert(types?.contains { $0 == 7 } ?? false)
    }

    func test_resolve_returnsVersionID_inDIDDocumentMetadata() async throws {
        Mock(
            url: URL(string: "https://diddht.tbddev.org/9tjoow45ef1hksoo96bmzkwwy3mhme95d7fsi3ezjyjghmp75qyo")!,
            statusCode: 200,
            data: [
                .get: Data.fromHexString(
                    """
                    ea33e704f3a48a3392f54b28744cdfb4e24780699f92ba7df62fd486d2a2cda3f263e1c6bcbd\
                    75d438be7316e5d6e94b13e98151f599cfecefad0b37432bd90a0000000065b0ed1600008400\
                    0000000300000000035f6b30045f6469643439746a6f6f773435656631686b736f6f3936626d\
                    7a6b777779336d686d653935643766736933657a6a796a67686d70373571796f000010000100\
                    001c2000373669643d303b743d303b6b3d5f464d49553174425a63566145502d437536715542\
                    6c66466f5f73665332726c4630675362693239323445045f747970045f6469643439746a6f6f\
                    773435656631686b736f6f3936626d7a6b777779336d686d653935643766736933657a6a796a\
                    67686d70373571796f000010000100001c2000070669643d372c36045f6469643439746a6f6f\
                    773435656631686b736f6f3936626d7a6b777779336d686d653935643766736933657a6a796a\
                    67686d70373571796f000010000100001c20002726763d303b766d3d6b303b617574683d6b30\
                    3b61736d3d6b303b64656c3d6b303b696e763d6b30
                    """
                )!
            ]
        ).register()

        let didURI = "did:dht:9tjoow45ef1hksoo96bmzkwwy3mhme95d7fsi3ezjyjghmp75qyo"
        let didResolutionResult = await DIDDHT.Resolver().resolve(didURI: didURI)

        XCTAssertNotNil(didResolutionResult.didDocumentMetadata.versionId)
    }
}
