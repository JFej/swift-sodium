import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

extension Sodium {
  /// Role-aware session-key agreement using X25519 and BLAKE2b.
  public enum KeyExchange: Sendable {
    /// A shareable key-exchange public key.
    public struct PublicKey: Hashable, Sendable {
      let data: Data

      /// Creates a public key from raw bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidKeyLength(expected: Self.byteCount, actual: data.count)
        }
        self.data = data
      }

      /// The required public-key size.
      public static var byteCount: Int { Int(crypto_kx_publickeybytes()) }

      /// The key's raw representation.
      public var dataRepresentation: Data { data }
    }

    /// A secret key-exchange key.
    public struct SecretKey: Sendable {
      fileprivate let bytes: SecureBytes

      /// Creates a secret key from raw bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidKeyLength(expected: Self.byteCount, actual: data.count)
        }
        bytes = SecureBytes(data)
      }

      init(_ bytes: [UInt8]) { self.bytes = SecureBytes(bytes) }

      /// The required secret-key size.
      public static var byteCount: Int { Int(crypto_kx_secretkeybytes()) }

      /// Provides temporary read-only access to raw key bytes.
      public func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
      ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
      }
    }

    /// A deterministic key-pair seed.
    public struct Seed: Sendable {
      fileprivate let bytes: SecureBytes

      /// Generates a random seed.
      public init() throws { bytes = SecureBytes(try randomData(count: Self.byteCount)) }

      /// Creates a seed from raw bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidSeedLength(expected: Self.byteCount, actual: data.count)
        }
        bytes = SecureBytes(data)
      }

      /// The required seed size.
      public static var byteCount: Int { Int(crypto_kx_seedbytes()) }
    }

    /// A matching key-exchange key pair.
    public struct KeyPair: Sendable {
      /// The shareable public key.
      public let publicKey: PublicKey

      /// The private key.
      public let secretKey: SecretKey

      /// Generates a random key pair.
      public init() throws {
        try Sodium.initialize()
        var publicBytes = [UInt8](repeating: 0, count: PublicKey.byteCount)
        var secretBytes = [UInt8](repeating: 0, count: SecretKey.byteCount)
        guard crypto_kx_keypair(&publicBytes, &secretBytes) == 0 else {
          throw SodiumError.operationFailed
        }
        publicKey = try PublicKey(data: publicBytes)
        secretKey = SecretKey(secretBytes)
        secretBytes.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
      }

      /// Derives a deterministic key pair from a seed.
      public init(seed: Seed) throws {
        try Sodium.initialize()
        var publicBytes = [UInt8](repeating: 0, count: PublicKey.byteCount)
        var secretBytes = [UInt8](repeating: 0, count: SecretKey.byteCount)
        let status = seed.bytes.withUnsafeBytes { seedBytes in
          crypto_kx_seed_keypair(
            &publicBytes,
            &secretBytes,
            seedBytes.bindMemory(to: UInt8.self).baseAddress!
          )
        }
        guard status == 0 else { throw SodiumError.operationFailed }
        publicKey = try PublicKey(data: publicBytes)
        secretKey = SecretKey(secretBytes)
        secretBytes.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
      }
    }

    /// Directional keys for one side of a session.
    public struct SessionKeys: Sendable {
      /// The key used to receive data from the peer.
      public let receive: SessionKey

      /// The key used to transmit data to the peer.
      public let transmit: SessionKey
    }

    /// A secret directional session key.
    public struct SessionKey: Sendable {
      private let bytes: SecureBytes

      init(_ bytes: [UInt8]) { self.bytes = SecureBytes(bytes) }

      /// The session-key size.
      public static var byteCount: Int { Int(crypto_kx_sessionkeybytes()) }

      /// Provides temporary read-only access to raw session-key bytes.
      public func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
      ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
      }
    }

    /// Derives directional keys for the client side of a session.
    public static func clientSessionKeys(
      client: KeyPair,
      serverPublicKey: PublicKey
    ) throws -> SessionKeys {
      try sessionKeys(local: client, peer: serverPublicKey, isClient: true)
    }

    /// Derives directional keys for the server side of a session.
    public static func serverSessionKeys(
      server: KeyPair,
      clientPublicKey: PublicKey
    ) throws -> SessionKeys {
      try sessionKeys(local: server, peer: clientPublicKey, isClient: false)
    }

    private static func sessionKeys(
      local: KeyPair,
      peer: PublicKey,
      isClient: Bool
    ) throws -> SessionKeys {
      try Sodium.initialize()
      var receive = [UInt8](repeating: 0, count: SessionKey.byteCount)
      var transmit = [UInt8](repeating: 0, count: SessionKey.byteCount)
      let status = local.secretKey.bytes.withUnsafeBytes { secretBytes in
        local.publicKey.data.withUnsafeBytes { publicBytes in
          peer.data.withUnsafeBytes { peerBytes in
            if isClient {
              crypto_kx_client_session_keys(
                &receive,
                &transmit,
                publicBytes.bindMemory(to: UInt8.self).baseAddress!,
                secretBytes.bindMemory(to: UInt8.self).baseAddress!,
                peerBytes.bindMemory(to: UInt8.self).baseAddress!
              )
            } else {
              crypto_kx_server_session_keys(
                &receive,
                &transmit,
                publicBytes.bindMemory(to: UInt8.self).baseAddress!,
                secretBytes.bindMemory(to: UInt8.self).baseAddress!,
                peerBytes.bindMemory(to: UInt8.self).baseAddress!
              )
            }
          }
        }
      }
      guard status == 0 else {
        receive.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
        transmit.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
        throw SodiumError.operationFailed
      }
      defer {
        receive.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
        transmit.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
      }
      return SessionKeys(receive: SessionKey(receive), transmit: SessionKey(transmit))
    }
  }
}
