import Sodium
import Testing

import struct Foundation.Data

@Suite("Randomized cryptographic properties")
struct RandomizedCryptoTests {
  @Test("Symmetric operations round trip deterministic randomized inputs")
  func symmetricRoundTrips() throws {
    var generator = DeterministicTestGenerator(seed: 0x5A17_C0DE)
    let secretBoxKey = try Sodium.SecretBox.Key(data: generator.data(count: 32))
    let aeadKey = try Sodium.AEAD.XChaCha20Poly1305.Key(data: generator.data(count: 32))

    for length in testLengths {
      let message = generator.data(count: length)
      let additionalData = generator.data(count: Int(generator.next() % 65))
      let secretBoxNonce = try Sodium.SecretBox.Nonce(data: generator.data(count: 24))
      let aeadNonce = try Sodium.AEAD.XChaCha20Poly1305.Nonce(
        data: generator.data(count: 24)
      )

      let secretBox = try Sodium.SecretBox.seal(
        message,
        using: secretBoxKey,
        nonce: secretBoxNonce
      )
      let aead = try Sodium.AEAD.XChaCha20Poly1305.seal(
        message,
        authenticating: additionalData,
        using: aeadKey,
        nonce: aeadNonce
      )

      #expect(try Sodium.SecretBox.open(secretBox, using: secretBoxKey) == message)
      #expect(
        try Sodium.AEAD.XChaCha20Poly1305.open(
          aead,
          authenticating: additionalData,
          using: aeadKey
        ) == message
      )
    }
  }

  @Test("Streaming hashes are independent of chunk boundaries")
  func streamingChunkBoundaries() throws {
    var generator = DeterministicTestGenerator(seed: 0xB1A2_E2B0)
    let message = generator.data(count: 16_385)
    let expected = try Sodium.GenericHash.hash(message, byteCount: 64)

    for chunkSize in [1, 3, 31, 64, 255, 1_024, 4_096] {
      let stream = try Sodium.GenericHash.stream(byteCount: 64)
      var offset = 0
      while offset < message.count {
        let end = min(offset + chunkSize, message.count)
        try stream.update(message[offset..<end])
        offset = end
      }
      #expect(try stream.finalize() == expected)
    }
  }

  @Test("Signatures authenticate deterministic randomized inputs")
  func signingProperties() throws {
    var generator = DeterministicTestGenerator(seed: 0xED25_5190)
    let keyPair = try Sodium.Signing.KeyPair(
      seed: Sodium.Signing.Seed(data: generator.data(count: 32))
    )

    for length in testLengths {
      let message = generator.data(count: length)
      let signature = try Sodium.Signing.sign(message, using: keyPair.secretKey)
      #expect(
        Sodium.Signing.isValid(signature, authenticating: message, using: keyPair.publicKey)
      )

      var changed = message
      if changed.isEmpty {
        changed.append(1)
      } else {
        changed[changed.startIndex] ^= 1
      }
      #expect(
        !Sodium.Signing.isValid(signature, authenticating: changed, using: keyPair.publicKey)
      )
    }
  }

  private var testLengths: [Int] {
    [0, 1, 2, 15, 16, 17, 31, 32, 33, 255, 256, 257, 1_023, 1_024, 4_097]
  }
}

private struct DeterministicTestGenerator: RandomNumberGenerator {
  private var state: UInt64

  init(seed: UInt64) { state = seed }

  mutating func next() -> UInt64 {
    state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
    return state
  }

  mutating func data(count: Int) -> Data {
    var output = Data()
    output.reserveCapacity(count)
    var value: UInt64 = 0
    for index in 0..<count {
      if index.isMultiple(of: MemoryLayout<UInt64>.size) {
        value = next()
      }
      output.append(UInt8(truncatingIfNeeded: value))
      value >>= 8
    }
    return output
  }
}
