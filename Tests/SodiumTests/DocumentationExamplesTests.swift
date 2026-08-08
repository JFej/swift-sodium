import Sodium
import Testing

import struct Foundation.Data

@Suite("Documentation examples")
struct DocumentationExamplesTests {
  @Test("Shared-key encryption example")
  func secretBoxExample() throws {
    let key = try Sodium.SecretBox.Key()
    let sealedBox = try Sodium.SecretBox.seal(Data("Hello".utf8), using: key)
    let plaintext = try Sodium.SecretBox.open(sealedBox, using: key)

    #expect(String(decoding: plaintext, as: UTF8.self) == "Hello")
  }

  @Test("Associated-data encryption example")
  func aeadExample() throws {
    let key = try Sodium.AEAD.XChaCha20Poly1305.Key()
    let metadata = Data("record:42".utf8)
    let sealedBox = try Sodium.AEAD.XChaCha20Poly1305.seal(
      Data("payload".utf8),
      authenticating: metadata,
      using: key
    )

    #expect(
      try Sodium.AEAD.XChaCha20Poly1305.open(
        sealedBox,
        authenticating: metadata,
        using: key
      ) == Data("payload".utf8)
    )
  }
}
