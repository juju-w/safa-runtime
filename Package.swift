// swift-tools-version: 6.1

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
        .library(name: "SAFABroker", targets: ["SAFABroker"]),
        .library(name: "SAFACLI", targets: ["SAFACLI"]),
        .library(name: "SAFAAskPass", targets: ["SAFAAskPass"]),
        .executable(name: "safa", targets: ["SAFACLIExecutable"]),
        .executable(name: "safa-broker", targets: ["SAFABrokerExecutable"]),
        .executable(name: "safa-askpass", targets: ["SAFAAskPassExecutable"]),
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
            dependencies: ["SAFACrypto", "SAFADomain", "SAFATransport"],
            swiftSettings: strictConcurrency
        ),
        .target(
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
            name: "SAFABrokerExecutable",
            dependencies: ["SAFABroker"],
            swiftSettings: strictConcurrency
        ),
        .target(
            name: "SAFACLI",
            dependencies: [
                "SAFAProtocol",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: strictConcurrency
        ),
        .executableTarget(
            name: "SAFACLIExecutable",
            dependencies: ["SAFACLI"],
            swiftSettings: strictConcurrency
        ),
        .target(
            name: "SAFAAskPass",
            dependencies: ["SAFAProtocol"],
            swiftSettings: strictConcurrency
        ),
        .executableTarget(
            name: "SAFAAskPassExecutable",
            dependencies: ["SAFAAskPass"],
            swiftSettings: strictConcurrency
        ),
        .target(
            name: "SAFATestFixtures",
            dependencies: ["SAFACrypto", "SAFADomain", "SAFATransport"],
            path: "Tests/Fixtures",
            swiftSettings: strictConcurrency
        ),
        .testTarget(
            name: "SAFADomainTests",
            dependencies: ["SAFADomain", "SAFAPolicy"],
            path: "Tests/Unit",
            swiftSettings: strictConcurrency
        ),
        .testTarget(
            name: "SAFAProtocolContractTests",
            dependencies: ["SAFACLI", "SAFADomain", "SAFAProtocol"],
            path: "Tests/Contract",
            swiftSettings: strictConcurrency
        ),
        .testTarget(
            name: "SAFAIntegrationTests",
            dependencies: [
                "SAFAAskPass",
                "SAFABroker",
                "SAFACLI",
                "SAFACrypto",
                "SAFADomain",
                "SAFAProtocol",
                "SAFASSH",
                "SAFATestFixtures",
                "SAFATransport",
            ],
            path: "Tests/Integration",
            swiftSettings: strictConcurrency
        ),
        .testTarget(
            name: "SAFASecurityTests",
            dependencies: [
                "SAFAAskPass",
                "SAFABroker",
                "SAFACrypto",
                "SAFADomain",
                "SAFAProtocol",
                "SAFASSH",
                "SAFATestFixtures",
                "SAFATransport",
            ],
            path: "Tests/Security",
            swiftSettings: strictConcurrency
        ),
    ],
    swiftLanguageModes: [.v6]
)
