#!/usr/bin/env swift
import Foundation

struct Bundle: Decodable {
  struct Artifact: Decodable {
    struct Variant: Decodable {
      struct Metadata: Decodable {
        let headerPaths: [String]
        let moduleMapPath: String?
      }

      let path: String
      let supportedTriples: [String]
      let staticLibraryMetadata: Metadata
    }

    let type: String
    let version: String
    let variants: [Variant]
  }

  let schemaVersion: String
  let artifacts: [String: Artifact]
}

enum ValidationError: Error, CustomStringConvertible {
  case usage
  case invalidSchema(String)
  case missingArtifact
  case invalidType(String)
  case missingPath(String)
  case duplicateTriple(String)
  case emptyVariants
  case invalidWindowsLibrary(String)
  case invalidUmbrellaHeader

  var description: String {
    switch self {
      case .usage: return "Usage: ValidateArtifactBundle.swift <CSodium.artifactbundle>"
      case .invalidSchema(let schema): return "Unsupported schema version: \(schema)"
      case .missingArtifact: return "CSodium artifact is missing"
      case .invalidType(let type): return "Expected staticLibrary, found \(type)"
      case .missingPath(let path): return "Referenced path does not exist: \(path)"
      case .duplicateTriple(let triple): return "Triple occurs in multiple variants: \(triple)"
      case .emptyVariants: return "Artifact contains no variants"
      case .invalidWindowsLibrary(let path):
        return "Windows variants must provide sodium.lib, found \(path)"
      case .invalidUmbrellaHeader:
        return "CSodium.h must define SODIUM_STATIC before including sodium.h"
    }
  }
}

do {
  guard CommandLine.arguments.count == 2 else { throw ValidationError.usage }
  let root = URL(filePath: CommandLine.arguments[1], directoryHint: .isDirectory)
  let info = root.appending(path: "info.json")
  let bundle = try JSONDecoder().decode(Bundle.self, from: Data(contentsOf: info))
  guard bundle.schemaVersion == "1.0" else {
    throw ValidationError.invalidSchema(bundle.schemaVersion)
  }
  guard let artifact = bundle.artifacts["CSodium"] else {
    throw ValidationError.missingArtifact
  }
  guard artifact.type == "staticLibrary" else {
    throw ValidationError.invalidType(artifact.type)
  }
  guard !artifact.variants.isEmpty else { throw ValidationError.emptyVariants }

  let umbrellaHeader = root.appending(path: "include/CSodium.h")
  guard let umbrellaContents = try? String(contentsOf: umbrellaHeader, encoding: .utf8),
    let staticDefinition = umbrellaContents.range(of: "#define SODIUM_STATIC 1"),
    let sodiumInclude = umbrellaContents.range(of: "#include \"sodium.h\""),
    staticDefinition.lowerBound < sodiumInclude.lowerBound
  else {
    throw ValidationError.invalidUmbrellaHeader
  }

  var triples = Set<String>()
  for variant in artifact.variants {
    if variant.supportedTriples.contains(where: { $0.contains("windows-msvc") }),
      URL(filePath: variant.path).lastPathComponent != "sodium.lib"
    {
      throw ValidationError.invalidWindowsLibrary(variant.path)
    }
    let paths =
      [variant.path]
      + variant.staticLibraryMetadata.headerPaths
      + [variant.staticLibraryMetadata.moduleMapPath].compactMap { $0 }
    for path in paths where !FileManager.default.fileExists(atPath: root.appending(path: path).path)
    {
      throw ValidationError.missingPath(path)
    }
    for triple in variant.supportedTriples {
      guard triples.insert(triple).inserted else {
        throw ValidationError.duplicateTriple(triple)
      }
    }
  }
  print("Validated \(artifact.variants.count) variants covering \(triples.count) triples")
} catch {
  FileHandle.standardError.write(Data("error: \(error)\n".utf8))
  exit(1)
}
