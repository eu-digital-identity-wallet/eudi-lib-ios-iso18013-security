// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "MdocSecurity18013",
    platforms: [.macOS(.v15), .iOS(.v17), .watchOS(.v10)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "MdocSecurity18013",
            targets: ["MdocSecurity18013"]),
    ],
    dependencies: [
        .package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model.git", from: "0.27.1"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.13.1"),
        .package(url: "https://github.com/apple/swift-certificates.git", .upToNextMajor(from: "1.0.0")),
		.package(url: "https://github.com/apple/swift-docc-plugin", from: "1.5.0"),
        .package(url: "https://github.com/beatt83/jose-swift.git", from: "6.0.5"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "MdocSecurity18013",
            dependencies: [
                .product(name: "MdocDataModel18013", package: "eudi-lib-ios-iso18013-data-model"),
                .product(name: "X509", package: "swift-certificates"),
                .target(name: "EudiEtsi1196x2", condition: .when(platforms: [.iOS])),
                .product(name: "jose-swift", package: "jose-swift", condition: .when(platforms: [.iOS, .macOS])),
            ],
            swiftSettings: [
                .enableUpcomingFeature("InferIsolatedConformances"),
                .enableUpcomingFeature("NonisolatedNonsendingByDefault")
            ]
        ),
        .testTarget(
            name: "MdocSecurity18013Tests",
            dependencies: ["MdocSecurity18013"],
            resources: [.process("Resources")]
        ),
        .binaryTarget(
            name: "EudiEtsi1196x2",
            url: "https://github.com/eu-digital-identity-wallet/eudi-lib-kmp-etsi-1196x2/releases/download/v0.4.0-alpha.3/EudiEtsi1196x2.xcframework.zip",
            checksum: "f8bb43a93e4dcd0555f9791edc75a2817b1d344ad0c3b4cf9550ee09dcbd730c"
        )
    ]
)
