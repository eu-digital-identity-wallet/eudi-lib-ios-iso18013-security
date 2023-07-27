// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "MdocSecurity18013",
    platforms: [.macOS(.v12), .iOS(.v13), .watchOS(.v9)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "MdocSecurity18013",
            targets: ["MdocSecurity18013"]),
    ],
    dependencies: [
        .package(path: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model.git"), 
        .package(url: "https://github.com/apple/swift-log.git", branch: "main"),
        .package(url: "https://github.com/filom/ASN1Decoder", from: "1.8.0")],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "MdocSecurity18013", dependencies: ["MdocDataModel18013", "ASN1Decoder", .product(name: "Logging", package: "swift-log")]),
        .testTarget(
            name: "MdocSecurity18013Tests",
            dependencies: ["MdocSecurity18013"]),
    ]
)
