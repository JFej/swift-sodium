import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

extension Sodium {
  /// Domain-separated subkey derivation from one high-entropy root key.
  public enum KeyDerivation: Sendable {
    /// A high-entropy root key.
    public struct Key: Sendable {
      private let bytes: SecureBytes

      /// Generates a random root key.
      public init() throws {
        try Sodium.initialize()
        var storage = [UInt8](repeating: 0, count: Self.byteCount)
        crypto_kdf_keygen(&storage)
        bytes = SecureBytes(storage)
        storage.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
      }

      /// Creates a root key from raw bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidKeyLength(expected: Self.byteCount, actual: data.count)
        }
        bytes = SecureBytes(data)
      }

      /// The required root-key size.
      public static var byteCount: Int { Int(crypto_kdf_keybytes()) }

      /// Provides temporary read-only access to raw key bytes.
      public func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
      ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
      }
    }

    /// An eight-byte application-specific domain separator.
    public struct Context: Hashable, Sendable {
      let data: Data

      /// Creates a context from exactly eight bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidContextLength(expected: Self.byteCount, actual: data.count)
        }
        self.data = data
      }

      /// Creates a context from an eight-byte UTF-8 string.
      public init(_ value: String) throws {
        try self.init(data: Data(value.utf8))
      }

      /// The required context size.
      public static var byteCount: Int { Int(crypto_kdf_contextbytes()) }
    }

    /// A derived secret subkey.
    public struct Subkey: Sendable {
      private let bytes: SecureBytes

      init(_ data: Data) { bytes = SecureBytes(data) }

      /// The subkey size.
      public var byteCount: Int { bytes.count }

      /// Provides temporary read-only access to raw subkey bytes.
      public func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
      ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
      }
    }

    /// The minimum supported subkey size.
    public static var minimumSubkeyByteCount: Int { Int(crypto_kdf_bytes_min()) }

    /// The maximum supported subkey size.
    public static var maximumSubkeyByteCount: Int { Int(crypto_kdf_bytes_max()) }

    /// Derives a domain-separated subkey.
    public static func deriveSubkey(
      byteCount: Int,
      id: UInt64,
      context: Context,
      from key: Key
    ) throws -> Subkey {
      try Sodium.initialize()
      guard (minimumSubkeyByteCount...maximumSubkeyByteCount).contains(byteCount) else {
        throw SodiumError.invalidDigestLength(
          minimum: minimumSubkeyByteCount,
          maximum: maximumSubkeyByteCount,
          actual: byteCount
        )
      }
      var output = Data(count: byteCount)
      let status = key.withUnsafeBytes { keyBytes in
        context.data.withUnsafeBytes { contextBytes in
          output.withUnsafeMutableBytes { outputBytes in
            crypto_kdf_derive_from_key(
              outputBytes.bindMemory(to: UInt8.self).baseAddress!,
              byteCount,
              id,
              contextBytes.bindMemory(to: CChar.self).baseAddress!,
              keyBytes.bindMemory(to: UInt8.self).baseAddress!
            )
          }
        }
      }
      guard status == 0 else { throw SodiumError.operationFailed }
      return Subkey(output)
    }
  }
}
