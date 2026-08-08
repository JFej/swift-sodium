import Sodium
import Testing

import struct Foundation.Data

@Suite("SecretStream")
struct SecretStreamTests {
  @Test("Ordered chunks preserve data and tags")
  func roundTrip() throws {
    let key = try Sodium.SecretStream.Key()
    let encryptor = try Sodium.SecretStream.Encryptor(key: key)
    let context = Data("file-v1".utf8)
    let first = try encryptor.push(Data("first".utf8), additionalData: context)
    let second = try encryptor.push(Data("second".utf8), tag: .push)
    let final = try encryptor.push(Data("final".utf8), tag: .final)

    let decryptor = try Sodium.SecretStream.Decryptor(key: key, header: encryptor.header)
    let openedFirst = try decryptor.pull(first, additionalData: context)
    let openedSecond = try decryptor.pull(second)
    let openedFinal = try decryptor.pull(final)

    #expect(openedFirst.data == Data("first".utf8))
    #expect(openedFirst.tag == .message)
    #expect(openedSecond.data == Data("second".utf8))
    #expect(openedSecond.tag == .push)
    #expect(openedFinal.data == Data("final".utf8))
    #expect(openedFinal.tag == .final)
    #expect(throws: SodiumError.invalidState) {
      try decryptor.pull(final)
    }
  }

  @Test("Wrong additional data is rejected")
  func additionalDataMismatch() throws {
    let key = try Sodium.SecretStream.Key()
    let encryptor = try Sodium.SecretStream.Encryptor(key: key)
    let ciphertext = try encryptor.push(
      Data("chunk".utf8),
      additionalData: Data("correct".utf8)
    )
    let decryptor = try Sodium.SecretStream.Decryptor(key: key, header: encryptor.header)

    #expect(throws: SodiumError.authenticationFailed) {
      try decryptor.pull(ciphertext, additionalData: Data("wrong".utf8))
    }
  }
}
