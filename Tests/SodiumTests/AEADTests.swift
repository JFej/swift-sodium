import Sodium
import Testing

import struct Foundation.Data

@Suite("XChaCha20-Poly1305")
struct AEADTests {
  @Test("Round trip with associated data")
  func roundTrip() throws {
    let key = try Sodium.AEAD.XChaCha20Poly1305.Key()
    let message = Data("authenticated secret".utf8)
    let context = Data("protocol-v1".utf8)
    let sealed = try Sodium.AEAD.XChaCha20Poly1305.seal(
      message,
      authenticating: context,
      using: key
    )

    #expect(
      try Sodium.AEAD.XChaCha20Poly1305.open(
        sealed,
        authenticating: context,
        using: key
      ) == message
    )
    #expect(try Sodium.AEAD.XChaCha20Poly1305.SealedBox(combined: sealed.combined) == sealed)
  }

  @Test("Wrong associated data is rejected")
  func associatedDataMismatch() throws {
    let key = try Sodium.AEAD.XChaCha20Poly1305.Key()
    let sealed = try Sodium.AEAD.XChaCha20Poly1305.seal(
      Data("secret".utf8),
      authenticating: Data("correct".utf8),
      using: key
    )

    #expect(throws: SodiumError.authenticationFailed) {
      try Sodium.AEAD.XChaCha20Poly1305.open(
        sealed,
        authenticating: Data("wrong".utf8),
        using: key
      )
    }
  }

  @Test("Empty message round trip")
  func emptyMessage() throws {
    let key = try Sodium.AEAD.XChaCha20Poly1305.Key()
    let sealed = try Sodium.AEAD.XChaCha20Poly1305.seal(Data(), using: key)

    #expect(try Sodium.AEAD.XChaCha20Poly1305.open(sealed, using: key).isEmpty)
  }
}
