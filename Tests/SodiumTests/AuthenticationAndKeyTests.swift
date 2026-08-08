import Sodium
import Testing

import struct Foundation.Data

@Suite("Authentication")
struct AuthenticationTests {
  @Test("Valid tags authenticate the message")
  func authenticatesMessage() throws {
    let key = try Sodium.Authentication.Key()
    let message = Data("authenticated".utf8)
    let tag = try Sodium.Authentication.authenticate(message, using: key)

    try Sodium.Authentication.verify(tag, authenticating: message, using: key)
    #expect(Sodium.Authentication.isValid(tag, authenticating: message, using: key))
    #expect(!Sodium.Authentication.isValid(tag, authenticating: Data("changed".utf8), using: key))
  }
}

@Suite("Key derivation")
struct KeyDerivationTests {
  @Test("Context and subkey identifier separate derived keys")
  func domainSeparation() throws {
    let key = try Sodium.KeyDerivation.Key(data: Data(repeating: 7, count: 32))
    let context = try Sodium.KeyDerivation.Context("AppKeys1")
    let first = try Sodium.KeyDerivation.deriveSubkey(
      byteCount: 32,
      id: 1,
      context: context,
      from: key
    )
    let second = try Sodium.KeyDerivation.deriveSubkey(
      byteCount: 32,
      id: 2,
      context: context,
      from: key
    )

    #expect(copy(first) != copy(second))
    #expect(first.byteCount == 32)
  }

  @Test("Context is exactly eight bytes")
  func validatesContext() {
    #expect(throws: SodiumError.invalidContextLength(expected: 8, actual: 5)) {
      try Sodium.KeyDerivation.Context("short")
    }
  }

  private func copy(_ key: Sodium.KeyDerivation.Subkey) -> Data {
    key.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
  }
}

@Suite("Key exchange")
struct KeyExchangeTests {
  @Test("Client and server derive matching directional keys")
  func exchangesDirectionalKeys() throws {
    let client = try Sodium.KeyExchange.KeyPair()
    let server = try Sodium.KeyExchange.KeyPair()
    let clientKeys = try Sodium.KeyExchange.clientSessionKeys(
      client: client,
      serverPublicKey: server.publicKey
    )
    let serverKeys = try Sodium.KeyExchange.serverSessionKeys(
      server: server,
      clientPublicKey: client.publicKey
    )

    #expect(copy(clientKeys.transmit) == copy(serverKeys.receive))
    #expect(copy(clientKeys.receive) == copy(serverKeys.transmit))
    #expect(copy(clientKeys.receive) != copy(clientKeys.transmit))
  }

  private func copy(_ key: Sodium.KeyExchange.SessionKey) -> Data {
    key.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
  }
}
