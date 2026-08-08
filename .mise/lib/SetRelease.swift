#!/usr/bin/env swift
import Foundation

enum ReleaseError: Error, CustomStringConvertible {
  case usage
  case invalidVersion(String)
  case invalidChecksum(String)
  case markerNotFound(String)

  var description: String {
    switch self {
      case .usage: return "Usage: SetRelease.swift <version> <64-character-checksum>"
      case .invalidVersion(let value): return "Invalid semantic version: \(value)"
      case .invalidChecksum(let value): return "Invalid SHA-256 checksum: \(value)"
      case .markerNotFound(let marker): return "Could not find release marker: \(marker)"
    }
  }
}

func replacing(_ pattern: String, with replacement: String, in input: String) throws -> String {
  let expression = try NSRegularExpression(pattern: pattern)
  let range = NSRange(input.startIndex..<input.endIndex, in: input)
  guard expression.firstMatch(in: input, range: range) != nil else {
    throw ReleaseError.markerNotFound(pattern)
  }
  return expression.stringByReplacingMatches(in: input, range: range, withTemplate: replacement)
}

do {
  guard CommandLine.arguments.count == 3 else { throw ReleaseError.usage }
  let version = CommandLine.arguments[1]
  let checksum = CommandLine.arguments[2]
  guard
    version.range(of: #"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$"#, options: .regularExpression) != nil
  else {
    throw ReleaseError.invalidVersion(version)
  }
  guard checksum.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
    throw ReleaseError.invalidChecksum(checksum)
  }

  let packageURL = URL(filePath: FileManager.default.currentDirectoryPath)
    .appending(path: "Package.swift")
  var package = try String(contentsOf: packageURL, encoding: .utf8)
  package = try replacing(
    #"let artifactVersion = "[^"]+""#,
    with: "let artifactVersion = \"\(version)\"",
    in: package
  )
  package = try replacing(
    #"let artifactChecksum = "[0-9a-f]+""#,
    with: "let artifactChecksum = \"\(checksum)\"",
    in: package
  )
  try package.write(to: packageURL, atomically: true, encoding: .utf8)
  print("Updated Package.swift for \(version)")
} catch {
  FileHandle.standardError.write(Data("error: \(error)\n".utf8))
  exit(1)
}
