#!/usr/bin/env swift
import Foundation

struct Bundle: Decodable {
  struct Artifact: Decodable {
    struct Variant: Decodable {
      let supportedTriples: [String]
    }

    let variants: [Variant]
  }

  let artifacts: [String: Artifact]
}

enum MatrixError: Error, CustomStringConvertible {
  case usage
  case missingArtifact
  case missingTriples([String])
  case unexpectedTriples([String])

  var description: String {
    switch self {
      case .usage:
        return "Usage: ValidateReleaseMatrix.swift <CSodium.artifactbundle>"
      case .missingArtifact:
        return "CSodium artifact is missing"
      case .missingTriples(let triples):
        return "Release is missing target triples: \(triples.joined(separator: ", "))"
      case .unexpectedTriples(let triples):
        return "Release contains unexpected target triples: \(triples.joined(separator: ", "))"
    }
  }
}

let appleTriples: Set<String> = [
  "arm64-apple-ios",
  "arm64-apple-ios-macabi",
  "arm64-apple-ios-simulator",
  "arm64-apple-macosx",
  "arm64-apple-tvos",
  "arm64-apple-tvos-simulator",
  "arm64-apple-watchos",
  "arm64-apple-watchos-simulator",
  "arm64-apple-xros",
  "arm64-apple-xros-simulator",
  "arm64_32-apple-watchos",
  "x86_64-apple-ios-macabi",
  "x86_64-apple-ios-simulator",
  "x86_64-apple-macosx",
  "x86_64-apple-tvos-simulator",
  "x86_64-apple-watchos-simulator",
  "x86_64-apple-xros-simulator",
]

let nativeTriples: Set<String> = [
  "aarch64-unknown-linux-gnu",
  "aarch64-unknown-windows-msvc",
  "wasm32-unknown-wasi",
  "x86_64-unknown-linux-gnu",
  "x86_64-unknown-windows-msvc",
]

let androidTriples = Set(
  ["aarch64", "armv7", "x86_64"]
    .flatMap { architecture in
      (28...36).map { "\(architecture)-unknown-linux-android\($0)" }
    }
)

do {
  guard CommandLine.arguments.count == 2 else { throw MatrixError.usage }
  let root = URL(filePath: CommandLine.arguments[1], directoryHint: .isDirectory)
  let data = try Data(contentsOf: root.appending(path: "info.json"))
  let bundle = try JSONDecoder().decode(Bundle.self, from: data)
  guard let artifact = bundle.artifacts["CSodium"] else { throw MatrixError.missingArtifact }

  let expected = appleTriples.union(nativeTriples).union(androidTriples)
  let actual = Set(artifact.variants.flatMap(\.supportedTriples))
  let missing = expected.subtracting(actual).sorted()
  let unexpected = actual.subtracting(expected).sorted()
  guard missing.isEmpty else { throw MatrixError.missingTriples(missing) }
  guard unexpected.isEmpty else { throw MatrixError.unexpectedTriples(unexpected) }

  print("Validated complete release matrix with \(actual.count) target triples")
} catch {
  FileHandle.standardError.write(Data("error: \(error)\n".utf8))
  exit(1)
}
