import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

extension Sodium {
  /// Authenticated encryption with associated data.
  public enum AEAD: Sendable {
    /// XChaCha20-Poly1305 with a 192-bit nonce.
    public enum XChaCha20Poly1305: Sendable {
      /// An XChaCha20-Poly1305 secret key.
      public struct Key: Sendable {
        fileprivate let bytes: SecureBytes

        /// Generates a random key.
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
        public static var byteCount: Int {
          Int(crypto_aead_xchacha20poly1305_ietf_keybytes())
        }

        /// Provides temporary read-only access to the key bytes.
        public func withUnsafeBytes<Result>(
          _ body: (UnsafeRawBufferPointer) throws -> Result
        ) rethrows -> Result {
          try bytes.withUnsafeBytes(body)
        }
      }

      /// A unique public nonce for one encryption operation.
      public struct Nonce: Hashable, Sendable {
        fileprivate let data: Data

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
        public static var byteCount: Int {
          Int(crypto_aead_xchacha20poly1305_ietf_npubbytes())
        }

        /// The nonce's raw representation.
        public var dataRepresentation: Data { data }
      }

      /// Authenticated ciphertext and its public nonce.
      public struct SealedBox: Hashable, Sendable {
        /// The nonce used for encryption.
        public let nonce: Nonce

        /// Ciphertext containing the authentication tag.
        public let ciphertext: Data

        /// Creates a sealed box from validated components.
        public init(nonce: Nonce, ciphertext: Data) throws {
          guard ciphertext.count >= XChaCha20Poly1305.authenticationTagByteCount else {
            throw SodiumError.authenticationFailed
          }
          self.nonce = nonce
          self.ciphertext = ciphertext
        }

        /// Creates a sealed box from `nonce || authenticatedCiphertext`.
        public init<D: DataProtocol>(combined: D) throws {
          let combined = Data(combined)
          let minimum = Nonce.byteCount + XChaCha20Poly1305.authenticationTagByteCount
          guard combined.count >= minimum else { throw SodiumError.authenticationFailed }
          nonce = try Nonce(data: combined.prefix(Nonce.byteCount))
          ciphertext = Data(combined.dropFirst(Nonce.byteCount))
        }

        /// `nonce || authenticatedCiphertext`.
        public var combined: Data { nonce.dataRepresentation + ciphertext }
      }

      /// The authentication tag size.
      public static var authenticationTagByteCount: Int {
        Int(crypto_aead_xchacha20poly1305_ietf_abytes())
      }

      /// Encrypts and authenticates a message without associated data.
      public static func seal<M: DataProtocol>(
        _ message: M,
        using key: Key,
        nonce: Nonce? = nil
      ) throws -> SealedBox {
        try seal(message, authenticating: Data(), using: key, nonce: nonce)
      }

      /// Encrypts a message and authenticates additional non-confidential data.
      public static func seal<M: DataProtocol, A: DataProtocol>(
        _ message: M,
        authenticating additionalData: A,
        using key: Key,
        nonce: Nonce? = nil
      ) throws -> SealedBox {
        try Sodium.initialize()
        let message = Data(message)
        let additionalData = Data(additionalData)
        let nonce = try nonce ?? Nonce()
        var ciphertext = Data(count: message.count + authenticationTagByteCount)
        var ciphertextCount: UInt64 = 0

        let status = key.withUnsafeBytes { keyBytes in
          nonce.data.withUnsafeBytes { nonceBytes in
            withUnsafeBytePointer(to: message) { messagePointer, messageCount in
              withUnsafeBytePointer(to: additionalData) { additionalPointer, additionalCount in
                ciphertext.withUnsafeMutableBytes { ciphertextBytes in
                  crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
                    &ciphertextCount,
                    messagePointer,
                    UInt64(messageCount),
                    additionalPointer,
                    UInt64(additionalCount),
                    nil,
                    nonceBytes.bindMemory(to: UInt8.self).baseAddress!,
                    keyBytes.bindMemory(to: UInt8.self).baseAddress!
                  )
                }
              }
            }
          }
        }
        guard status == 0, ciphertextCount == UInt64(ciphertext.count) else {
          throw SodiumError.operationFailed
        }
        return try SealedBox(nonce: nonce, ciphertext: ciphertext)
      }

      /// Authenticates and decrypts a sealed box without associated data.
      public static func open(
        _ sealedBox: SealedBox,
        using key: Key
      ) throws -> Data {
        try open(sealedBox, authenticating: Data(), using: key)
      }

      /// Authenticates associated data and decrypts a sealed box.
      public static func open<A: DataProtocol>(
        _ sealedBox: SealedBox,
        authenticating additionalData: A,
        using key: Key
      ) throws -> Data {
        try Sodium.initialize()
        guard sealedBox.ciphertext.count >= authenticationTagByteCount else {
          throw SodiumError.authenticationFailed
        }
        let additionalData = Data(additionalData)
        var message = Data(count: sealedBox.ciphertext.count - authenticationTagByteCount)
        var messageCount: UInt64 = 0

        let status = key.withUnsafeBytes { keyBytes in
          sealedBox.nonce.data.withUnsafeBytes { nonceBytes in
            sealedBox.ciphertext.withUnsafeBytes { ciphertextBytes in
              withUnsafeBytePointer(to: additionalData) { additionalPointer, additionalCount in
                withUnsafeMutableBytePointer(to: &message) { messagePointer, _ in
                  crypto_aead_xchacha20poly1305_ietf_decrypt(
                    messagePointer,
                    &messageCount,
                    nil,
                    ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
                    UInt64(sealedBox.ciphertext.count),
                    additionalPointer,
                    UInt64(additionalCount),
                    nonceBytes.bindMemory(to: UInt8.self).baseAddress!,
                    keyBytes.bindMemory(to: UInt8.self).baseAddress!
                  )
                }
              }
            }
          }
        }
        guard status == 0, messageCount == UInt64(message.count) else {
          throw SodiumError.authenticationFailed
        }
        return message
      }
    }
  }
}
