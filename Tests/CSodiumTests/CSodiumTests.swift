import CSodium
import Testing

@Suite("CSodium interoperability")
struct CSodiumTests {
  @Test("C module initializes and reports its pinned version")
  func initializationAndVersion() {
    #expect(sodium_init() >= 0)
    #expect(String(cString: sodium_version_string()) == "1.0.22")
  }

  @Test("C module exposes expected high-level primitive sizes")
  func primitiveSizes() {
    #expect(crypto_secretbox_keybytes() == 32)
    #expect(crypto_secretbox_noncebytes() == 24)
    #expect(crypto_aead_xchacha20poly1305_ietf_keybytes() == 32)
    #expect(crypto_aead_xchacha20poly1305_ietf_npubbytes() == 24)
    #expect(crypto_sign_publickeybytes() == 32)
    #expect(crypto_sign_bytes() == 64)
  }

  @Test("C authentication API matches RFC 4231")
  func authenticationVector() {
    var key = [UInt8](repeating: 0, count: Int(crypto_auth_keybytes()))
    key.replaceSubrange(0..<4, with: Array("Jefe".utf8))
    let message = Array("what do ya want for nothing?".utf8)
    var tag = [UInt8](repeating: 0, count: Int(crypto_auth_bytes()))

    #expect(crypto_auth(&tag, message, UInt64(message.count), key) == 0)
    #expect(
      tag == [
        0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2,
        0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56, 0xe0, 0xa3,
        0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6,
        0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54,
      ]
    )
  }
}
