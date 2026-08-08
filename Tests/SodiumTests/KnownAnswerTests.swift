import Sodium
import Testing

import struct Foundation.Data

@Suite("Known-answer vectors")
struct KnownAnswerTests {
  @Test("libsodium XChaCha20-Poly1305 test vector")
  func xChaCha20Poly1305Vector() throws {
    let key = try Sodium.AEAD.XChaCha20Poly1305.Key(
      data: bytes(in: 0x80...0x9f)
    )
    let nonce = try Sodium.AEAD.XChaCha20Poly1305.Nonce(
      data: hex("07000000404142434445464748494a4b4c4d4e4f50515253")
    )
    let message = Data(
      ("Ladies and Gentlemen of the class of '99: If I could offer you "
        + "only one tip for the future, sunscreen would be it.")
        .utf8
    )
    let additionalData = try hex("50515253c0c1c2c3c4c5c6c7")
    let sealedBox = try Sodium.AEAD.XChaCha20Poly1305.seal(
      message,
      authenticating: additionalData,
      using: key,
      nonce: nonce
    )

    #expect(
      Sodium.Utilities.hexadecimal(sealedBox.ciphertext)
        == "f8ebea4875044066fc162a0604e171feecfb3d20425248563bcfd5a155dcc47b"
        + "bda70b86e5ab9b55002bd1274c02db35321acd7af8b2e2d25015e136b7679458"
        + "e9f43243bf719d639badb5feac03f80a19a96ef10cb1d15333a837b90946ba38"
        + "54ee74da3f2585efc7e1e170e17e15e563e77601f4f85cafa8e5877614e143e6"
        + "8420"
    )
  }

  @Test("RFC 4231 HMAC-SHA-512/256 test case 2")
  func authenticationRFC4231Vector() throws {
    var keyData = Data("Jefe".utf8)
    keyData.append(Data(repeating: 0, count: Sodium.Authentication.Key.byteCount - keyData.count))
    let key = try Sodium.Authentication.Key(data: keyData)
    let tag = try Sodium.Authentication.authenticate(
      Data("what do ya want for nothing?".utf8),
      using: key
    )

    #expect(
      Sodium.Utilities.hexadecimal(tag.dataRepresentation)
        == "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
    )
  }

  @Test("libsodium BLAKE2b KDF test vector")
  func keyDerivationVector() throws {
    let key = try Sodium.KeyDerivation.Key(data: bytes(in: 0...31))
    let context = try Sodium.KeyDerivation.Context("KDF test")
    let subkey = try Sodium.KeyDerivation.deriveSubkey(
      byteCount: 64,
      id: 0,
      context: context,
      from: key
    )

    #expect(
      subkey.withUnsafeBytes { Sodium.Utilities.hexadecimal(Data($0)) }
        == "a0c724404728c8bb95e5433eb6a9716171144d61efb23e74b873fcbeda51d807"
        + "1b5d70aae12066dfc94ce943f145aa176c055040c3dd73b0a15e36254d450614"
    )
  }

  @Test("RFC 8032 Ed25519 test vector 1")
  func ed25519RFC8032Vector1() throws {
    let seed = try Sodium.Signing.Seed(
      data: Sodium.Utilities.data(
        hexadecimal: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
      )
    )
    let keys = try Sodium.Signing.KeyPair(seed: seed)
    let signature = try Sodium.Signing.sign(Data(), using: keys.secretKey)

    #expect(
      Sodium.Utilities.hexadecimal(keys.publicKey.dataRepresentation)
        == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    #expect(
      Sodium.Utilities.hexadecimal(signature.dataRepresentation)
        == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
  }

  @Test("libsodium deterministic-random test vector")
  func deterministicRandomVector() throws {
    let seed = try Sodium.Random.Seed(
      data: Sodium.Utilities.data(
        hexadecimal: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
      )
    )

    #expect(
      Sodium.Utilities.hexadecimal(try Sodium.Random.deterministicBytes(count: 10, seed: seed))
        == "444dc0602207c270b93f"
    )
  }

  private func hex(_ value: String) throws -> Data {
    try Sodium.Utilities.data(hexadecimal: value)
  }

  private func bytes(in range: ClosedRange<Int>) -> Data {
    Data(range.map(UInt8.init))
  }
}
