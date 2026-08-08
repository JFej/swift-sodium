// swift-tools-version: 6.3

import PackageDescription

let package = Package(
  name: "SodiumBenchmarks",
  platforms: [.macOS(.v14)],
  dependencies: [
    .package(name: "swift-sodium", path: "..")
  ],
  targets: [
    .executableTarget(
      name: "SodiumBenchmarks",
      dependencies: [
        .product(name: "Sodium", package: "swift-sodium")
      ]
    )
  ]
)
