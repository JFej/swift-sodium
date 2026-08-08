import Sodium
import Testing

import struct Foundation.Data

@Suite("SecretBox")
struct SecretBoxTests {
  @Test("Round trip")
  func roundTrip() throws {
    let key = try Sodium.SecretBox.Key()
    let message = Data("Tobit.Chat".utf8)

    let sealedBox = try Sodium.SecretBox.seal(message, using: key)

    #expect(try Sodium.SecretBox.open(sealedBox, using: key) == message)
  }

  @Test("Combined representation round trips")
  func combinedRepresentation() throws {
    let key = try Sodium.SecretBox.Key()
    let original = try Sodium.SecretBox.seal(Data("message".utf8), using: key)
    let decoded = try Sodium.SecretBox.SealedBox(combined: original.combined)

    #expect(decoded == original)
  }

  @Test("Tampering fails authentication")
  func rejectsTampering() throws {
    let key = try Sodium.SecretBox.Key()
    let sealedBox = try Sodium.SecretBox.seal(Data("message".utf8), using: key)
    var ciphertext = sealedBox.ciphertext
    ciphertext[0] ^= 1
    let tampered = try Sodium.SecretBox.SealedBox(nonce: sealedBox.nonce, ciphertext: ciphertext)

    #expect(throws: SodiumError.authenticationFailed) {
      try Sodium.SecretBox.open(tampered, using: key)
    }
  }

  @Test("Invalid key length is rejected")
  func rejectsInvalidKey() {
    #expect(throws: SodiumError.invalidKeyLength(expected: 32, actual: 1)) {
      try Sodium.SecretBox.Key(data: Data([0]))
    }
  }

  @Test("Detached authentication round trip")
  func detachedRoundTrip() throws {
    let key = try Sodium.SecretBox.Key()
    let message = Data("detached".utf8)
    let sealedBox = try Sodium.SecretBox.sealDetached(message, using: key)

    #expect(sealedBox.ciphertext.count == message.count)
    #expect(try Sodium.SecretBox.open(sealedBox, using: key) == message)
  }
}
