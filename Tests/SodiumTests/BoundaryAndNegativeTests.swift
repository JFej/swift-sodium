import Sodium
import Testing

import struct Foundation.Data

@Suite("Boundary and negative behavior")
struct BoundaryAndNegativeTests {
  @Test("All fixed-width inputs reject incorrect lengths")
  func fixedWidthValidation() {
    #expect(throws: SodiumError.invalidKeyLength(expected: 32, actual: 31)) {
      try Sodium.SecretBox.Key(data: Data(repeating: 0, count: 31))
    }
    #expect(throws: SodiumError.invalidNonceLength(expected: 24, actual: 23)) {
      try Sodium.SecretBox.Nonce(data: Data(repeating: 0, count: 23))
    }
    #expect(throws: SodiumError.invalidKeyLength(expected: 32, actual: 33)) {
      try Sodium.AEAD.XChaCha20Poly1305.Key(data: Data(repeating: 0, count: 33))
    }
    #expect(throws: SodiumError.invalidSeedLength(expected: 32, actual: 0)) {
      try Sodium.Signing.Seed(data: Data())
    }
    #expect(throws: SodiumError.invalidContextLength(expected: 8, actual: 9)) {
      try Sodium.KeyDerivation.Context("nine-byte")
    }
    #expect(throws: SodiumError.invalidEncoding) {
      try Sodium.PasswordHash.Salt(data: Data(repeating: 0, count: 15))
    }
  }

  @Test("Digest and subkey boundaries are enforced")
  func variableWidthValidation() throws {
    #expect(
      throws: SodiumError.invalidDigestLength(
        minimum: Sodium.GenericHash.minimumDigestByteCount,
        maximum: Sodium.GenericHash.maximumDigestByteCount,
        actual: Sodium.GenericHash.minimumDigestByteCount - 1
      )
    ) {
      try Sodium.GenericHash.hash(
        Data(),
        byteCount: Sodium.GenericHash.minimumDigestByteCount - 1
      )
    }

    let root = try Sodium.KeyDerivation.Key()
    let context = try Sodium.KeyDerivation.Context("Bounds01")
    #expect(
      throws: SodiumError.invalidDigestLength(
        minimum: Sodium.KeyDerivation.minimumSubkeyByteCount,
        maximum: Sodium.KeyDerivation.maximumSubkeyByteCount,
        actual: Sodium.KeyDerivation.maximumSubkeyByteCount + 1
      )
    ) {
      try Sodium.KeyDerivation.deriveSubkey(
        byteCount: Sodium.KeyDerivation.maximumSubkeyByteCount + 1,
        id: 0,
        context: context,
        from: root
      )
    }
  }

  @Test("Every changed AEAD ciphertext byte is rejected")
  func aeadRejectsEverySingleByteMutation() throws {
    let key = try Sodium.AEAD.XChaCha20Poly1305.Key()
    let additionalData = Data("metadata".utf8)
    let sealed = try Sodium.AEAD.XChaCha20Poly1305.seal(
      Data("authenticated payload".utf8),
      authenticating: additionalData,
      using: key
    )

    for index in sealed.ciphertext.indices {
      var ciphertext = sealed.ciphertext
      ciphertext[index] ^= 1
      let changed = try Sodium.AEAD.XChaCha20Poly1305.SealedBox(
        nonce: sealed.nonce,
        ciphertext: ciphertext
      )
      #expect(throws: SodiumError.authenticationFailed) {
        try Sodium.AEAD.XChaCha20Poly1305.open(
          changed,
          authenticating: additionalData,
          using: key
        )
      }
    }
  }

  @Test("Wrong keys and truncated data are rejected")
  func rejectsWrongKeysAndTruncation() throws {
    let key = try Sodium.SecretBox.Key()
    let wrongKey = try Sodium.SecretBox.Key()
    let sealed = try Sodium.SecretBox.seal(Data("payload".utf8), using: key)
    #expect(throws: SodiumError.authenticationFailed) {
      try Sodium.SecretBox.open(sealed, using: wrongKey)
    }
    let truncated = try Sodium.SecretBox.SealedBox(combined: sealed.combined.dropLast())
    #expect(throws: SodiumError.authenticationFailed) {
      try Sodium.SecretBox.open(truncated, using: key)
    }

    let recipient = try Sodium.PublicKeyBox.KeyPair()
    let otherRecipient = try Sodium.PublicKeyBox.KeyPair()
    let anonymous = try Sodium.PublicKeyBox.sealAnonymous(
      Data("private".utf8),
      to: recipient.publicKey
    )
    #expect(throws: SodiumError.authenticationFailed) {
      try Sodium.PublicKeyBox.openAnonymous(anonymous, using: otherRecipient)
    }
  }

  @Test("Stateful APIs reject use after finalization")
  func finalizedState() throws {
    let hash = try Sodium.GenericHash.stream()
    _ = try hash.finalize()
    #expect(throws: SodiumError.invalidState) { try hash.finalize() }

    let key = try Sodium.SecretStream.Key()
    let encryptor = try Sodium.SecretStream.Encryptor(key: key)
    _ = try encryptor.push(Data(), tag: .final)
    #expect(throws: SodiumError.invalidState) { try encryptor.push(Data()) }
    #expect(throws: SodiumError.invalidState) { try encryptor.rekey() }
  }

  @Test("Unicode passwords and empty messages are supported")
  func unicodeAndEmptyInputs() throws {
    let password = "🔐 pässwörd עברית 日本語"
    let hash = try Sodium.PasswordHash.hash(password)
    #expect(try Sodium.PasswordHash.verify(password, against: hash))

    let key = try Sodium.SecretBox.Key()
    let sealed = try Sodium.SecretBox.seal(Data(), using: key)
    #expect(try Sodium.SecretBox.open(sealed, using: key).isEmpty)
  }
}
