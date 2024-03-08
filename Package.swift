// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Web5",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        .library(
            name: "Web5",
            targets: ["Web5"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", from: "0.16.0"),
        .package(url: "https://github.com/swift-extras/swift-extras-base64.git", from: "0.7.0"),
        .package(url: "https://github.com/pointfreeco/swift-custom-dump.git", from: "1.1.2"),
        .package(url: "https://github.com/WeTransfer/Mocker.git", .upToNextMajor(from: "3.0.1")),
        .package(url: "https://github.com/allegro/swift-junit.git", from: "2.1.0"),
        .package(url: "https://github.com/flight-school/anycodable.git", from: "0.6.7"),
        .package(url: "https://github.com/Bouke/DNS.git", from: "1.2.0"),
        .package(url: "https://github.com/KittyMac/Sextant.git", .upToNextMinor(from: "0.4.0")),
        .package(url: "https://github.com/kylef/JSONSchema.swift.git", from: "0.6.0"),
        .package(url: "https://github.com/KittyMac/Hitch.git", from: "0.4.121")
    ],
    targets: [
        .target(
            name: "Web5",
            dependencies: [
                .product(name: "secp256k1", package: "secp256k1.swift"),
                .product(name: "ExtrasBase64", package: "swift-extras-base64"),
                .product(name: "AnyCodable", package: "anycodable"),
                .product(name: "DNS", package: "DNS"),
                .product(name: "Sextant", package: "sextant"),
                .product(name: "JSONSchema", package: "jsonschema.swift"),
                .product(name: "Hitch", package: "hitch")
            ]
        ),
        .testTarget(
            name: "Web5Tests",
            dependencies: [
                "Web5",
                .product(name: "CustomDump", package: "swift-custom-dump"),
                .product(name: "Mocker", package: "Mocker"),
            ]
        ),
        .testTarget(
            name: "Web5TestVectors",
            dependencies: [
                "Web5",
                .product(name: "CustomDump", package: "swift-custom-dump"),
                .product(name: "Mocker", package: "Mocker"),
                .product(name: "SwiftTestReporter", package: "swift-junit"),
            ],
            resources: [
                .copy("Resources/did"),
                .copy("web5-spec/test-vectors"),
            ]
        ),
    ]
)
