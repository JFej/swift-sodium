import Sodium
import Testing

import struct Foundation.Data

@Suite("PublicKeyBox")
struct PublicKeyBoxTests {
  @Test("Authenticated round trip")
  func authenticatedRoundTrip() throws {
    let sender = try Sodium.PublicKeyBox.KeyPair()
    let recipient = try Sodium.PublicKeyBox.KeyPair()
    let message = Data("private".utf8)

    let sealedBox = try Sodium.PublicKeyBox.seal(
      message,
      to: recipient.publicKey,
      authenticatedBy: sender.secretKey
    )

    let plaintext = try Sodium.PublicKeyBox.open(
      sealedBox,
      from: sender.publicKey,
      using: recipient.secretKey
    )
    #expect(plaintext == message)
  }

  @Test("Anonymous round trip")
  func anonymousRoundTrip() throws {
    let recipient = try Sodium.PublicKeyBox.KeyPair()
    let message = Data("anonymous".utf8)

    let sealedBox = try Sodium.PublicKeyBox.sealAnonymous(message, to: recipient.publicKey)

    #expect(try Sodium.PublicKeyBox.openAnonymous(sealedBox, using: recipient) == message)
  }

  @Test("Seeded keys are deterministic")
  func deterministicKeys() throws {
    let seed = try Sodium.PublicKeyBox.Seed(
      data: Data(repeating: 7, count: Sodium.PublicKeyBox.Seed.byteCount)
    )

    let first = try Sodium.PublicKeyBox.KeyPair(seed: seed)
    let second = try Sodium.PublicKeyBox.KeyPair(seed: seed)

    #expect(first.publicKey == second.publicKey)
  }
}
