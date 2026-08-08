import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

extension Sodium {
  /// Password hashing and verification using Argon2id.
  public enum PasswordHash: Sendable {
    /// The Argon2 algorithm used for raw key derivation.
    public enum Algorithm: Sendable {
      /// Argon2id 1.3, libsodium's current default.
      case argon2id

      /// Argon2i 1.3, for compatibility with protocols that require it.
      case argon2i

      var identifier: Int32 {
        switch self {
          case .argon2id: crypto_pwhash_alg_argon2id13()
          case .argon2i: crypto_pwhash_alg_argon2i13()
        }
      }
    }

    /// Resource limits for password hashing.
    public struct Limits: Hashable, Sendable {
      /// The CPU work factor.
      public let operations: UInt64

      /// The requested memory in bytes.
      public let memory: Int

      /// Creates explicit password-hashing limits.
      public init(operations: UInt64, memory: Int) {
        precondition(operations > 0)
        precondition(memory > 0)
        self.operations = operations
        self.memory = memory
      }

      /// Suitable for interactive authentication.
      public static var interactive: Self {
        Self(
          operations: UInt64(crypto_pwhash_opslimit_interactive()),
          memory: crypto_pwhash_memlimit_interactive()
        )
      }

      /// Suitable for background operations with moderate resource use.
      public static var moderate: Self {
        Self(
          operations: UInt64(crypto_pwhash_opslimit_moderate()),
          memory: crypto_pwhash_memlimit_moderate()
        )
      }

      /// Suitable for highly sensitive data on capable systems.
      public static var sensitive: Self {
        Self(
          operations: UInt64(crypto_pwhash_opslimit_sensitive()),
          memory: crypto_pwhash_memlimit_sensitive()
        )
      }
    }

    /// An encoded Argon2id password hash containing its salt and parameters.
    public struct Hash: Hashable, Sendable, CustomStringConvertible {
      /// The encoded libsodium string.
      public let encoded: String

      /// Creates a hash from an encoded libsodium string.
      public init(encoded: String) {
        self.encoded = encoded
      }

      /// The encoded libsodium password-hash string.
      public var description: String { encoded }
    }

    /// A public, randomly generated salt for raw password-based key derivation.
    public struct Salt: Hashable, Sendable {
      let data: Data

      /// Generates a random salt.
      public init() throws { data = try randomData(count: Self.byteCount) }

      /// Creates a salt from raw bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidEncoding
        }
        self.data = data
      }

      /// The required salt size.
      public static var byteCount: Int { Int(crypto_pwhash_saltbytes()) }

      /// The salt's raw representation.
      public var dataRepresentation: Data { data }
    }

    /// Secret bytes derived from a password and salt.
    public struct DerivedKey: Sendable {
      private let bytes: SecureBytes

      init(_ data: Data) { bytes = SecureBytes(data) }

      /// The derived-key size.
      public var byteCount: Int { bytes.count }

      /// Provides temporary read-only access to raw key bytes.
      public func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
      ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
      }
    }

    /// Hashes a password with an automatically generated salt.
    public static func hash(
      _ password: String,
      limits: Limits = .interactive
    ) throws -> Hash {
      try Sodium.initialize()
      let passwordBytes = Data(password.utf8)
      var output = [CChar](repeating: 0, count: Int(crypto_pwhash_strbytes()))
      let status = withUnsafeBytePointer(to: passwordBytes) { passwordPointer, passwordCount in
        crypto_pwhash_str(
          &output,
          passwordPointer,
          UInt64(passwordCount),
          limits.operations,
          limits.memory
        )
      }
      guard status == 0 else { throw SodiumError.passwordHashingFailed }
      let bytes = output.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
      return Hash(encoded: String(decoding: bytes, as: UTF8.self))
    }

    /// Verifies a password against an encoded hash.
    public static func verify(_ password: String, against hash: Hash) throws -> Bool {
      try Sodium.initialize()
      let passwordBytes = Data(password.utf8)
      return hash.encoded.withCString { encoded in
        withUnsafeBytePointer(to: passwordBytes) { passwordPointer, passwordCount in
          crypto_pwhash_str_verify(
            encoded,
            passwordPointer,
            UInt64(passwordCount)
          ) == 0
        }
      }
    }

    /// Returns whether a hash should be regenerated with the supplied limits.
    public static func needsRehash(_ hash: Hash, limits: Limits = .interactive) throws -> Bool {
      try Sodium.initialize()
      return hash.encoded.withCString { encoded in
        crypto_pwhash_str_needs_rehash(encoded, limits.operations, limits.memory) != 0
      }
    }

    /// Derives secret key material from a password and an explicit salt.
    ///
    /// Persist the salt, limits, algorithm, and output size alongside encrypted data.
    public static func deriveKey(
      from password: String,
      salt: Salt,
      byteCount: Int,
      limits: Limits = .interactive,
      algorithm: Algorithm = .argon2id
    ) throws -> DerivedKey {
      try Sodium.initialize()
      let minimum = Int(crypto_pwhash_bytes_min())
      let maximum = Int(crypto_pwhash_bytes_max())
      guard (minimum...maximum).contains(byteCount) else {
        throw SodiumError.invalidDigestLength(minimum: minimum, maximum: maximum, actual: byteCount)
      }
      let passwordBytes = Data(password.utf8)
      var output = Data(count: byteCount)
      let status = salt.data.withUnsafeBytes { saltBytes in
        withUnsafeBytePointer(to: passwordBytes) { passwordPointer, passwordCount in
          output.withUnsafeMutableBytes { outputBytes in
            crypto_pwhash(
              outputBytes.bindMemory(to: UInt8.self).baseAddress!,
              UInt64(byteCount),
              passwordPointer,
              UInt64(passwordCount),
              saltBytes.bindMemory(to: UInt8.self).baseAddress!,
              limits.operations,
              limits.memory,
              algorithm.identifier
            )
          }
        }
      }
      guard status == 0 else { throw SodiumError.passwordHashingFailed }
      return DerivedKey(output)
    }
  }
}
