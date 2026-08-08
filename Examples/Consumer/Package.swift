// swift-tools-version: 6.3

import PackageDescription

let package = Package(
  name: "SodiumConsumer",
  platforms: [.macOS(.v14)],
  dependencies: [
    .package(name: "swift-sodium", path: "../..")
  ],
  targets: [
    .executableTarget(
      name: "SodiumConsumer",
      dependencies: [
        .product(name: "Sodium", package: "swift-sodium")
      ]
    )
  ]
)
