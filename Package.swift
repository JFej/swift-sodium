// swift-tools-version: 6.3

import Foundation
import PackageDescription

let artifactVersion = "0.1.0"
let artifactChecksum = "0000000000000000000000000000000000000000000000000000000000000000"
let localArtifactPath = "Artifacts/CSodium.artifactbundle"
let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent()

let cSodiumTarget: Target =
  if FileManager.default.fileExists(
    atPath: packageRoot.appendingPathComponent(localArtifactPath).path
  ) {
    .binaryTarget(name: "CSodium", path: localArtifactPath)
  } else {
    .binaryTarget(
      name: "CSodium",
      url:
        "https://github.com/JFej/swift-sodium/releases/download/\(artifactVersion)/CSodium.artifactbundle.zip",
      checksum: artifactChecksum
    )
  }

let package = Package(
  name: "swift-sodium",
  platforms: [
    .macOS(.v14),
    .iOS(.v16),
    .tvOS(.v16),
    .watchOS(.v9),
    .visionOS(.v1),
  ],
  products: [
    .library(name: "CSodium", targets: ["CSodium"]),
    .library(name: "Sodium", targets: ["Sodium"]),
  ],
  dependencies: [
    .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.5.0")
  ],
  targets: [
    cSodiumTarget,
    .target(
      name: "Sodium",
      dependencies: ["CSodium"],
      swiftSettings: [
        .enableUpcomingFeature("ApproachableConcurrency")
      ]
    ),
    .testTarget(
      name: "SodiumTests",
      dependencies: ["Sodium"]
    ),
    .testTarget(
      name: "CSodiumTests",
      dependencies: ["CSodium"]
    ),
  ],
  swiftLanguageModes: [.v6]
)
