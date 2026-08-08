import Sodium
import Testing

import struct Foundation.Data

@Suite("Signing")
struct SigningTests {
  @Test("Valid signature")
  func validSignature() throws {
    let keys = try Sodium.Signing.KeyPair()
    let message = Data("signed".utf8)
    let signature = try Sodium.Signing.sign(message, using: keys.secretKey)

    try Sodium.Signing.verify(signature, authenticating: message, using: keys.publicKey)
    #expect(Sodium.Signing.isValid(signature, authenticating: message, using: keys.publicKey))
  }

  @Test("Modified message is rejected")
  func rejectsModifiedMessage() throws {
    let keys = try Sodium.Signing.KeyPair()
    let signature = try Sodium.Signing.sign(Data("original".utf8), using: keys.secretKey)

    #expect(
      !Sodium.Signing.isValid(
        signature,
        authenticating: Data("modified".utf8),
        using: keys.publicKey
      )
    )
  }

  @Test("Attached signature round trip")
  func attachedSignature() throws {
    let keys = try Sodium.Signing.KeyPair()
    let message = Data("attached".utf8)
    let signed = try Sodium.Signing.signAttached(message, using: keys.secretKey)

    #expect(try Sodium.Signing.open(signed, using: keys.publicKey) == message)
  }
}
