import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

extension Sodium {
  /// BLAKE2b hashing with optional authentication keys.
  public enum GenericHash: Sendable {
    /// An incremental BLAKE2b hashing operation.
    ///
    /// Stream instances are intentionally non-Sendable and may only be mutated by one task.
    public final class Stream {
      private let state: OpaquePointer
      private let digestByteCount: Int
      private var isFinalized = false

      fileprivate init(byteCount: Int, key: Key?) throws {
        digestByteCount = byteCount
        guard let stateMemory = sodium_malloc(crypto_generichash_statebytes()) else {
          throw SodiumError.operationFailed
        }
        state = OpaquePointer(stateMemory)
        let initialize: (UnsafeRawBufferPointer?) -> Int32 = { keyBytes in
          crypto_generichash_init(
            self.state,
            keyBytes?.bindMemory(to: UInt8.self).baseAddress,
            keyBytes?.count ?? 0,
            byteCount
          )
        }
        let status =
          if let key {
            key.withUnsafeBytes { initialize($0) }
          } else {
            initialize(nil)
          }
        guard status == 0 else {
          sodium_free(stateMemory)
          throw SodiumError.operationFailed
        }
      }

      deinit {
        sodium_free(UnsafeMutableRawPointer(state))
      }

      /// Adds another chunk to the digest.
      public func update<D: DataProtocol>(_ data: D) throws {
        guard !isFinalized else { throw SodiumError.invalidState }
        let data = Data(data)
        let status = withUnsafeBytePointer(to: data) { pointer, count in
          crypto_generichash_update(state, pointer, UInt64(count))
        }
        guard status == 0 else { throw SodiumError.operationFailed }
      }

      /// Finalizes and returns the digest.
      public func finalize() throws -> Data {
        guard !isFinalized else { throw SodiumError.invalidState }
        var digest = Data(count: digestByteCount)
        let status = digest.withUnsafeMutableBytes { digestBytes in
          crypto_generichash_final(
            state,
            digestBytes.bindMemory(to: UInt8.self).baseAddress!,
            digestByteCount
          )
        }
        guard status == 0 else { throw SodiumError.operationFailed }
        isFinalized = true
        return digest
      }
    }

    /// A secret BLAKE2b authentication key.
    public struct Key: Sendable {
      private let bytes: SecureBytes

      /// Generates a key using libsodium's recommended size.
      public init() throws {
        bytes = SecureBytes(try randomData(count: Self.recommendedByteCount))
      }

      /// Creates a key from raw bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard (Self.minimumByteCount...Self.maximumByteCount).contains(data.count) else {
          throw SodiumError.invalidKeyLength(
            expected: Self.recommendedByteCount, actual: data.count)
        }
        bytes = SecureBytes(data)
      }

      /// The smallest supported key size.
      public static var minimumByteCount: Int { Int(crypto_generichash_keybytes_min()) }

      /// The largest supported key size.
      public static var maximumByteCount: Int { Int(crypto_generichash_keybytes_max()) }

      /// libsodium's recommended key size.
      public static var recommendedByteCount: Int { Int(crypto_generichash_keybytes()) }

      fileprivate func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
      ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
      }
    }

    /// The smallest supported digest size.
    public static var minimumDigestByteCount: Int { Int(crypto_generichash_bytes_min()) }

    /// The largest supported digest size.
    public static var maximumDigestByteCount: Int { Int(crypto_generichash_bytes_max()) }

    /// libsodium's recommended digest size.
    public static var recommendedDigestByteCount: Int { Int(crypto_generichash_bytes()) }

    /// Hashes a message using BLAKE2b.
    public static func hash<D: DataProtocol>(
      _ message: D,
      byteCount: Int = recommendedDigestByteCount,
      key: Key? = nil
    ) throws -> Data {
      try Sodium.initialize()
      guard (minimumDigestByteCount...maximumDigestByteCount).contains(byteCount) else {
        throw SodiumError.invalidDigestLength(
          minimum: minimumDigestByteCount,
          maximum: maximumDigestByteCount,
          actual: byteCount
        )
      }

      let message = Data(message)
      var digest = Data(count: byteCount)

      let operation: (UnsafeRawBufferPointer?) -> Int32 = { keyBytes in
        withUnsafeBytePointer(to: message) { messagePointer, _ in
          digest.withUnsafeMutableBytes { digestBytes in
            crypto_generichash(
              digestBytes.bindMemory(to: UInt8.self).baseAddress!,
              byteCount,
              messagePointer,
              UInt64(message.count),
              keyBytes?.bindMemory(to: UInt8.self).baseAddress,
              keyBytes?.count ?? 0
            )
          }
        }
      }

      let status =
        if let key {
          key.withUnsafeBytes { operation($0) }
        } else {
          operation(nil)
        }

      guard status == 0 else { throw SodiumError.operationFailed }
      return digest
    }

    /// Creates an incremental BLAKE2b hashing operation.
    public static func stream(
      byteCount: Int = recommendedDigestByteCount,
      key: Key? = nil
    ) throws -> Stream {
      try Sodium.initialize()
      guard (minimumDigestByteCount...maximumDigestByteCount).contains(byteCount) else {
        throw SodiumError.invalidDigestLength(
          minimum: minimumDigestByteCount,
          maximum: maximumDigestByteCount,
          actual: byteCount
        )
      }
      return try Stream(byteCount: byteCount, key: key)
    }
  }
}
