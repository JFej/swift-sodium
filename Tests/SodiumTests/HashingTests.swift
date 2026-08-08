import Sodium
import Testing

import struct Foundation.Data

@Suite("Hashing")
struct HashingTests {
  @Test("Generic hashes are deterministic")
  func genericHash() throws {
    let message = Data("hash me".utf8)

    let first = try Sodium.GenericHash.hash(message)
    let second = try Sodium.GenericHash.hash(message)

    #expect(first == second)
    #expect(first.count == Sodium.GenericHash.recommendedDigestByteCount)
  }

  @Test("BLAKE2b-256 matches the published empty-message vector")
  func genericHashKnownAnswer() throws {
    let digest = try Sodium.GenericHash.hash(Data(), byteCount: 32)

    #expect(
      Sodium.Utilities.hexadecimal(digest)
        == "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
    )
  }

  @Test("Keyed hashes differ from unkeyed hashes")
  func keyedHash() throws {
    let message = Data("hash me".utf8)
    let key = try Sodium.GenericHash.Key()

    #expect(
      try Sodium.GenericHash.hash(message)
        != Sodium.GenericHash.hash(message, key: key)
    )
  }

  @Test("Streaming hash matches one-shot hash")
  func streamingHash() throws {
    let stream = try Sodium.GenericHash.stream(byteCount: 32)
    try stream.update(Data("streaming ".utf8))
    try stream.update(Data("message".utf8))

    #expect(
      try stream.finalize()
        == Sodium.GenericHash.hash(Data("streaming message".utf8), byteCount: 32)
    )
    #expect(throws: SodiumError.invalidState) {
      try stream.update(Data("too late".utf8))
    }
  }

  @Test("Password hashes verify")
  func passwordHash() throws {
    let hash = try Sodium.PasswordHash.hash("correct horse battery staple")

    #expect(try Sodium.PasswordHash.verify("correct horse battery staple", against: hash))
    #expect(try !Sodium.PasswordHash.verify("wrong", against: hash))
    #expect(try !Sodium.PasswordHash.needsRehash(hash, limits: .interactive))
    #expect(try Sodium.PasswordHash.needsRehash(hash, limits: .moderate))
  }

  @Test("Password-based key derivation is deterministic for stored parameters")
  func passwordKeyDerivation() throws {
    let salt = try Sodium.PasswordHash.Salt(data: Data(repeating: 3, count: 16))
    let first = try Sodium.PasswordHash.deriveKey(
      from: "password",
      salt: salt,
      byteCount: 32
    )
    let second = try Sodium.PasswordHash.deriveKey(
      from: "password",
      salt: salt,
      byteCount: 32
    )

    let firstData = first.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
    let secondData = second.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
    #expect(firstData == secondData)
  }
}
