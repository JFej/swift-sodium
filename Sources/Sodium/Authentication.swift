import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

extension Sodium {
  /// Symmetric message authentication using HMAC-SHA-512/256.
  public enum Authentication: Sendable {
    /// A secret authentication key.
    public struct Key: Sendable {
      private let bytes: SecureBytes

      /// Generates a random key.
      public init() throws {
        try Sodium.initialize()
        var storage = [UInt8](repeating: 0, count: Self.byteCount)
        crypto_auth_keygen(&storage)
        bytes = SecureBytes(storage)
        storage.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
      }

      /// Creates a key from raw bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidKeyLength(expected: Self.byteCount, actual: data.count)
        }
        bytes = SecureBytes(data)
      }

      /// The required key size.
      public static var byteCount: Int { Int(crypto_auth_keybytes()) }

      /// Provides temporary read-only access to raw key bytes.
      public func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
      ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
      }
    }

    /// A message authentication code.
    public struct Tag: Hashable, Sendable {
      let data: Data

      /// Creates a tag from raw bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else { throw SodiumError.authenticationFailed }
        self.data = data
      }

      /// The tag size.
      public static var byteCount: Int { Int(crypto_auth_bytes()) }

      /// The tag's raw representation.
      public var dataRepresentation: Data { data }
    }

    /// Authenticates a message.
    public static func authenticate<D: DataProtocol>(
      _ message: D,
      using key: Key
    ) throws -> Tag {
      try Sodium.initialize()
      let message = Data(message)
      var tag = Data(count: Tag.byteCount)
      let status = key.withUnsafeBytes { keyBytes in
        withUnsafeBytePointer(to: message) { messagePointer, _ in
          tag.withUnsafeMutableBytes { tagBytes in
            crypto_auth(
              tagBytes.bindMemory(to: UInt8.self).baseAddress!,
              messagePointer,
              UInt64(message.count),
              keyBytes.bindMemory(to: UInt8.self).baseAddress!
            )
          }
        }
      }
      guard status == 0 else { throw SodiumError.operationFailed }
      return try Tag(data: tag)
    }

    /// Verifies a message authentication code.
    public static func verify<D: DataProtocol>(
      _ tag: Tag,
      authenticating message: D,
      using key: Key
    ) throws {
      try Sodium.initialize()
      let message = Data(message)
      let status = key.withUnsafeBytes { keyBytes in
        tag.data.withUnsafeBytes { tagBytes in
          withUnsafeBytePointer(to: message) { messagePointer, _ in
            crypto_auth_verify(
              tagBytes.bindMemory(to: UInt8.self).baseAddress!,
              messagePointer,
              UInt64(message.count),
              keyBytes.bindMemory(to: UInt8.self).baseAddress!
            )
          }
        }
      }
      guard status == 0 else { throw SodiumError.authenticationFailed }
    }

    /// Returns whether a message authentication code is valid.
    public static func isValid<D: DataProtocol>(
      _ tag: Tag,
      authenticating message: D,
      using key: Key
    ) -> Bool {
      (try? verify(tag, authenticating: message, using: key)) != nil
    }
  }
}
