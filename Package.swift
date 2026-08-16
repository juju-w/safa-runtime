// swift-tools-version: 6.2

import PackageDescription

let strictConcurrency: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("ExistentialAny"),
]

let package = Package(
    name: "SAFA",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "SAFADomain", targets: ["SAFADomain"]),
        .library(name: "SAFAProtocol", targets: ["SAFAProtocol"]),
        .library(name: "SAFACrypto", targets: ["SAFACrypto"]),
        .library(name: "SAFAPolicy", targets: ["SAFAPolicy"]),
        .library(name: "SAFATransport", targets: ["SAFATransport"]),
        .library(name: "SAFASSH", targets: ["SAFASSH"]),
        .executable(name: "safa", targets: ["SAFACLI"]),
        .executable(name: "safa-broker", targets: ["SAFABroker"]),
        .executable(name: "safa-askpass", targets: ["SAFAAskPass"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-argument-parser.git",
            from: "1.8.2"
        )
    ],
    targets: [
        .target(name: "SAFADomain", swiftSettings: strictConcurrency),
        .target(
            name: "SAFAProtocol",
            dependencies: ["SAFADomain"],
            swiftSettings: strictConcurrency
        ),
        .target(
            name: "SAFACrypto",
            dependencies: ["SAFADomain"],
            swiftSettings: strictConcurrency
        ),
        .target(
            name: "SAFAPolicy",
            dependencies: ["SAFADomain"],
            swiftSettings: strictConcurrency
        ),
        .target(
            name: "SAFATransport",
            dependencies: ["SAFADomain"],
            swiftSettings: strictConcurrency
        ),
        .target(
            name: "SAFASSH",
            dependencies: ["SAFADomain", "SAFATransport"],
            swiftSettings: strictConcurrency
        ),
        .executableTarget(
            name: "SAFABroker",
            dependencies: [
                "SAFACrypto",
                "SAFADomain",
                "SAFAPolicy",
                "SAFAProtocol",
                "SAFASSH",
                "SAFATransport",
            ],
            swiftSettings: strictConcurrency
        ),
        .executableTarget(
            name: "SAFACLI",
            dependencies: [
                "SAFAProtocol",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: strictConcurrency
        ),
        .executableTarget(
            name: "SAFAAskPass",
            dependencies: ["SAFAProtocol"],
            swiftSettings: strictConcurrency
        ),
        .target(
            name: "SAFATestFixtures",
            dependencies: ["SAFACrypto", "SAFADomain"],
            path: "Tests/Fixtures",
            swiftSettings: strictConcurrency
        ),
        .testTarget(
            name: "SAFADomainTests",
            dependencies: ["SAFADomain"],
            path: "Tests/Unit",
            swiftSettings: strictConcurrency
        ),
        .testTarget(
            name: "SAFAProtocolContractTests",
            dependencies: ["SAFADomain", "SAFAProtocol"],
            path: "Tests/Contract",
            swiftSettings: strictConcurrency
        ),
        .testTarget(
            name: "SAFAIntegrationTests",
            dependencies: ["SAFACrypto", "SAFADomain", "SAFATestFixtures"],
            path: "Tests/Integration",
            swiftSettings: strictConcurrency
        ),
        .testTarget(
            name: "SAFASecurityTests",
            dependencies: ["SAFACrypto", "SAFADomain", "SAFAProtocol", "SAFATestFixtures"],
            path: "Tests/Security",
            swiftSettings: strictConcurrency
        ),
    ],
    swiftLanguageModes: [.v6]
)
