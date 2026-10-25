// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CertLab",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "CertLab", targets: ["CertLab"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.6.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0" ..< "5.0.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "CertLabCore",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
        .executableTarget(name: "CertLab", dependencies: ["CertLabCore"]),
        .testTarget(
            name: "CertLabCoreTests",
            dependencies: [
                "CertLabCore",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
    ]
)
