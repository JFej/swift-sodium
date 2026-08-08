import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

extension Sodium {
  /// Authenticated symmetric encryption using XSalsa20-Poly1305.
  public enum SecretBox: Sendable {
    /// A symmetric SecretBox key.
    public struct Key: Sendable {
      private let bytes: SecureBytes

      /// Generates a new random key.
      public init() throws {
        bytes = SecureBytes(try randomData(count: Self.byteCount))
      }

      /// Creates a key from its raw representation.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidKeyLength(expected: Self.byteCount, actual: data.count)
        }
        bytes = SecureBytes(data)
      }

      /// The required key size.
      public static var byteCount: Int { Int(crypto_secretbox_keybytes()) }

      /// Provides temporary read-only access to the raw key bytes.
      public func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
      ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
      }
    }

    /// A public, unique nonce for one SecretBox operation.
    public struct Nonce: Hashable, Sendable {
      let data: Data

      /// Generates a random nonce.
      public init() throws {
        data = try randomData(count: Self.byteCount)
      }

      /// Creates a nonce from its raw representation.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidNonceLength(expected: Self.byteCount, actual: data.count)
        }
        self.data = data
      }

      /// The required nonce size.
      public static var byteCount: Int { Int(crypto_secretbox_noncebytes()) }

      /// The nonce's raw representation.
      public var dataRepresentation: Data { data }
    }

    /// Authenticated ciphertext and its public nonce.
    public struct SealedBox: Hashable, Sendable {
      /// The nonce used to produce the ciphertext.
      public let nonce: Nonce

      /// Ciphertext containing the authentication tag.
      public let ciphertext: Data

      /// Creates a sealed box from validated components.
      public init(nonce: Nonce, ciphertext: Data) throws {
        guard ciphertext.count >= SecretBox.authenticationTagByteCount else {
          throw SodiumError.authenticationFailed
        }
        self.nonce = nonce
        self.ciphertext = ciphertext
      }

      /// Creates a sealed box from `nonce || authenticatedCiphertext`.
      public init<D: DataProtocol>(combined: D) throws {
        let combined = Data(combined)
        let minimum = Nonce.byteCount + SecretBox.authenticationTagByteCount
        guard combined.count >= minimum else {
          throw SodiumError.authenticationFailed
        }
        nonce = try Nonce(data: combined.prefix(Nonce.byteCount))
        ciphertext = combined.dropFirst(Nonce.byteCount)
      }

      /// `nonce || authenticatedCiphertext`.
      public var combined: Data {
        nonce.dataRepresentation + ciphertext
      }
    }

    /// Ciphertext with a detached authentication tag and public nonce.
    public struct DetachedBox: Hashable, Sendable {
      /// The nonce used to produce the ciphertext.
      public let nonce: Nonce

      /// Ciphertext with the same size as the plaintext.
      public let ciphertext: Data

      /// The detached authentication tag.
      public let authenticationTag: Data

      /// Creates a detached box from validated components.
      public init(nonce: Nonce, ciphertext: Data, authenticationTag: Data) throws {
        guard authenticationTag.count == SecretBox.authenticationTagByteCount else {
          throw SodiumError.authenticationFailed
        }
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.authenticationTag = authenticationTag
      }
    }

    /// The authentication tag size.
    public static var authenticationTagByteCount: Int { Int(crypto_secretbox_macbytes()) }

    /// Encrypts and authenticates a message.
    public static func seal<D: DataProtocol>(
      _ message: D,
      using key: Key,
      nonce: Nonce? = nil
    ) throws -> SealedBox {
      try Sodium.initialize()
      let nonce = try nonce ?? Nonce()
      let message = Data(message)
      var ciphertext = Data(count: message.count + authenticationTagByteCount)

      let status = key.withUnsafeBytes { keyBytes in
        nonce.data.withUnsafeBytes { nonceBytes in
          withUnsafeBytePointer(to: message) { messagePointer, _ in
            ciphertext.withUnsafeMutableBytes { ciphertextBytes in
              crypto_secretbox_easy(
                ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
                messagePointer,
                UInt64(message.count),
                nonceBytes.bindMemory(to: UInt8.self).baseAddress!,
                keyBytes.bindMemory(to: UInt8.self).baseAddress!
              )
            }
          }
        }
      }

      guard status == 0 else { throw SodiumError.operationFailed }
      return try SealedBox(nonce: nonce, ciphertext: ciphertext)
    }

    /// Authenticates and decrypts a sealed box.
    public static func open(_ sealedBox: SealedBox, using key: Key) throws -> Data {
      try Sodium.initialize()
      guard sealedBox.ciphertext.count >= authenticationTagByteCount else {
        throw SodiumError.authenticationFailed
      }

      var message = Data(count: sealedBox.ciphertext.count - authenticationTagByteCount)
      let status = key.withUnsafeBytes { keyBytes in
        sealedBox.nonce.data.withUnsafeBytes { nonceBytes in
          sealedBox.ciphertext.withUnsafeBytes { ciphertextBytes in
            withUnsafeMutableBytePointer(to: &message) { messagePointer, _ in
              crypto_secretbox_open_easy(
                messagePointer,
                ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
                UInt64(sealedBox.ciphertext.count),
                nonceBytes.bindMemory(to: UInt8.self).baseAddress!,
                keyBytes.bindMemory(to: UInt8.self).baseAddress!
              )
            }
          }
        }
      }

      guard status == 0 else { throw SodiumError.authenticationFailed }
      return message
    }

    /// Encrypts a message with a detached authentication tag.
    public static func sealDetached<D: DataProtocol>(
      _ message: D,
      using key: Key,
      nonce: Nonce? = nil
    ) throws -> DetachedBox {
      try Sodium.initialize()
      let nonce = try nonce ?? Nonce()
      let message = Data(message)
      var ciphertext = Data(count: message.count)
      var tag = Data(count: authenticationTagByteCount)
      let status = key.withUnsafeBytes { keyBytes in
        nonce.data.withUnsafeBytes { nonceBytes in
          withUnsafeBytePointer(to: message) { messagePointer, _ in
            ciphertext.withUnsafeMutableBytes { ciphertextBytes in
              tag.withUnsafeMutableBytes { tagBytes in
                crypto_secretbox_detached(
                  ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
                  tagBytes.bindMemory(to: UInt8.self).baseAddress!,
                  messagePointer,
                  UInt64(message.count),
                  nonceBytes.bindMemory(to: UInt8.self).baseAddress!,
                  keyBytes.bindMemory(to: UInt8.self).baseAddress!
                )
              }
            }
          }
        }
      }
      guard status == 0 else { throw SodiumError.operationFailed }
      return try DetachedBox(nonce: nonce, ciphertext: ciphertext, authenticationTag: tag)
    }

    /// Authenticates and decrypts detached ciphertext.
    public static func open(_ detachedBox: DetachedBox, using key: Key) throws -> Data {
      try Sodium.initialize()
      var message = Data(count: detachedBox.ciphertext.count)
      let status = key.withUnsafeBytes { keyBytes in
        detachedBox.nonce.data.withUnsafeBytes { nonceBytes in
          detachedBox.authenticationTag.withUnsafeBytes { tagBytes in
            detachedBox.ciphertext.withUnsafeBytes { ciphertextBytes in
              withUnsafeMutableBytePointer(to: &message) { messagePointer, _ in
                crypto_secretbox_open_detached(
                  messagePointer,
                  ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
                  tagBytes.bindMemory(to: UInt8.self).baseAddress!,
                  UInt64(detachedBox.ciphertext.count),
                  nonceBytes.bindMemory(to: UInt8.self).baseAddress!,
                  keyBytes.bindMemory(to: UInt8.self).baseAddress!
                )
              }
            }
          }
        }
      }
      guard status == 0 else { throw SodiumError.authenticationFailed }
      return message
    }
  }
}
