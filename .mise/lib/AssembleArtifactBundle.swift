#!/usr/bin/env swift
import Foundation

struct VariantMetadata: Decodable {
  let identifier: String
  let library: String
  let supportedTriples: [String]
}

struct BundleMetadata: Encodable {
  struct Artifact: Encodable {
    let type = "staticLibrary"
    let version: String
    let variants: [Variant]
  }

  struct Variant: Encodable {
    struct StaticLibraryMetadata: Encodable {
      let headerPaths = ["include"]
      let moduleMapPath = "include/module.modulemap"
    }

    let path: String
    let supportedTriples: [String]
    let staticLibraryMetadata = StaticLibraryMetadata()
  }

  let schemaVersion = "1.0"
  let artifacts: [String: Artifact]
}

enum AssemblyError: Error, CustomStringConvertible {
  case usage
  case noVariants(URL)
  case duplicateTriple(String)
  case missingFile(URL)
  case inconsistentHeaders(String)

  var description: String {
    switch self {
      case .usage:
        return
          "Usage: AssembleArtifactBundle.swift --variants <directory> --output <bundle> --version <version>"
      case .noVariants(let url):
        return "No variant metadata found in \(url.path)"
      case .duplicateTriple(let triple):
        return "Duplicate supported triple: \(triple)"
      case .missingFile(let url):
        return "Required file does not exist: \(url.path)"
      case .inconsistentHeaders(let identifier):
        return "Variant \(identifier) has headers that differ from the first variant"
    }
  }
}

func argument(named name: String) throws -> String {
  guard let index = CommandLine.arguments.firstIndex(of: name),
    CommandLine.arguments.indices.contains(index + 1)
  else { throw AssemblyError.usage }
  return CommandLine.arguments[index + 1]
}

func directoryDigest(_ directory: URL) throws -> String {
  let files = try FileManager.default.subpathsOfDirectory(atPath: directory.path).sorted()
  var hasher = Hasher()
  for file in files {
    let url = directory.appending(path: file)
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
      continue
    }
    if !isDirectory.boolValue {
      hasher.combine(file)
      hasher.combine(try Data(contentsOf: url))
    }
  }
  return String(hasher.finalize())
}

do {
  let variantsURL = URL(filePath: try argument(named: "--variants"), directoryHint: .isDirectory)
  let outputURL = URL(filePath: try argument(named: "--output"), directoryHint: .isDirectory)
  let version = try argument(named: "--version")
  let fileManager = FileManager.default
  let decoder = JSONDecoder()

  let metadataURLs =
    try fileManager.contentsOfDirectory(
      at: variantsURL,
      includingPropertiesForKeys: nil,
      options: [.skipsHiddenFiles]
    )
    .map { $0.appending(path: "metadata.json") }
    .filter { fileManager.fileExists(atPath: $0.path) }
    .sorted { $0.path < $1.path }

  guard !metadataURLs.isEmpty else { throw AssemblyError.noVariants(variantsURL) }

  if fileManager.fileExists(atPath: outputURL.path) {
    try fileManager.removeItem(at: outputURL)
  }
  try fileManager.createDirectory(at: outputURL, withIntermediateDirectories: true)
  let outputDist = outputURL.appending(path: "dist", directoryHint: .isDirectory)
  let outputInclude = outputURL.appending(path: "include", directoryHint: .isDirectory)
  try fileManager.createDirectory(at: outputDist, withIntermediateDirectories: true)

  var variants: [BundleMetadata.Variant] = []
  var triples = Set<String>()
  var referenceHeaderDigest: String?
  var copiedLicense = false

  for metadataURL in metadataURLs {
    let metadata = try decoder.decode(VariantMetadata.self, from: Data(contentsOf: metadataURL))
    let variantRoot = metadataURL.deletingLastPathComponent()
    let libraryURL = variantRoot.appending(path: metadata.library)
    let includeURL = variantRoot.appending(path: "include", directoryHint: .isDirectory)
    guard fileManager.fileExists(atPath: libraryURL.path) else {
      throw AssemblyError.missingFile(libraryURL)
    }
    guard fileManager.fileExists(atPath: includeURL.path) else {
      throw AssemblyError.missingFile(includeURL)
    }
    let licenseURL = variantRoot.appending(path: "LICENSE.libsodium")
    guard fileManager.fileExists(atPath: licenseURL.path) else {
      throw AssemblyError.missingFile(licenseURL)
    }

    for triple in metadata.supportedTriples {
      guard triples.insert(triple).inserted else { throw AssemblyError.duplicateTriple(triple) }
    }

    let headerDigest = try directoryDigest(includeURL)
    if let referenceHeaderDigest, referenceHeaderDigest != headerDigest {
      throw AssemblyError.inconsistentHeaders(metadata.identifier)
    } else if referenceHeaderDigest == nil {
      referenceHeaderDigest = headerDigest
      try fileManager.copyItem(at: includeURL, to: outputInclude)
    }
    if !copiedLicense {
      try fileManager.copyItem(
        at: licenseURL,
        to: outputURL.appending(path: "LICENSE.libsodium")
      )
      copiedLicense = true
    }

    let destinationDirectory = outputDist.appending(
      path: metadata.identifier, directoryHint: .isDirectory)
    try fileManager.createDirectory(at: destinationDirectory, withIntermediateDirectories: true)
    let destinationLibrary = destinationDirectory.appending(path: libraryURL.lastPathComponent)
    try fileManager.copyItem(at: libraryURL, to: destinationLibrary)
    variants.append(
      .init(
        path: "dist/\(metadata.identifier)/\(libraryURL.lastPathComponent)",
        supportedTriples: metadata.supportedTriples.sorted()
      )
    )
  }

  let umbrellaHeader = """
    #ifndef CSODIUM_H
    #define CSODIUM_H
    #define SODIUM_STATIC 1
    #include "sodium.h"
    #endif
    """
  try Data(umbrellaHeader.utf8).write(to: outputInclude.appending(path: "CSodium.h"))

  let moduleMap = """
    module CSodium [system] {
      umbrella header "CSodium.h"
      export *
    }
    """
  try Data(moduleMap.utf8).write(to: outputInclude.appending(path: "module.modulemap"))

  let bundle = BundleMetadata(
    artifacts: [
      "CSodium": .init(version: version, variants: variants)
    ]
  )
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
  try encoder.encode(bundle).write(to: outputURL.appending(path: "info.json"))
  print(
    "Assembled \(variants.count) variants covering \(triples.count) triples at \(outputURL.path)")
} catch {
  FileHandle.standardError.write(Data("error: \(error)\n".utf8))
  exit(1)
}
