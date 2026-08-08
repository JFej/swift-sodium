import Sodium
import Testing

import struct Foundation.Data

@Suite("Sodium")
struct SodiumTests {
  @Test("Library initializes")
  func initializes() throws {
    try Sodium.initialize()
    #expect(!Sodium.version.isEmpty)
    #expect(Sodium.version != "unknown")
  }

  @Test("Random bytes have requested size")
  func randomBytes() throws {
    #expect(try Sodium.Random.bytes(count: 64).count == 64)
  }

  @Test("Deterministic random bytes repeat for the same seed")
  func deterministicRandomBytes() throws {
    let seed = try Sodium.Random.Seed(
      data: Data(repeating: 7, count: Sodium.Random.Seed.byteCount)
    )
    let first = try Sodium.Random.deterministicBytes(count: 64, seed: seed)
    let second = try Sodium.Random.deterministicBytes(count: 64, seed: seed)

    #expect(first == second)
    #expect(first.count == 64)
  }

  @Test("Random generator integrates with the standard library")
  func randomNumberGenerator() {
    var generator = Sodium.Random.Generator()
    let value = UInt64.random(in: 0..<100, using: &generator)

    #expect(value < 100)
  }
}
