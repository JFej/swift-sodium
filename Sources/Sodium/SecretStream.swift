import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

extension Sodium {
  /// Ordered authenticated encryption for sequences and files.
  public enum SecretStream: Sendable {
    /// A SecretStream key.
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
        Int(crypto_secretstream_xchacha20poly1305_keybytes())
      }
    }

    /// A public header required to initialize the decrypting stream.
    public struct Header: Hashable, Sendable {
      fileprivate let data: Data

      /// Creates a header from its raw representation.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidEncoding
        }
        self.data = data
      }

      /// The required header size.
      public static var byteCount: Int {
        Int(crypto_secretstream_xchacha20poly1305_headerbytes())
      }

      /// The header's raw representation.
      public var dataRepresentation: Data { data }
    }

    /// Semantic boundary attached to an encrypted chunk.
    public enum Tag: Hashable, Sendable {
      /// A regular chunk.
      case message

      /// The end of a logical subsection.
      case push

      /// A chunk that also rotates the stream key.
      case rekey

      /// The final chunk. No subsequent chunks are valid.
      case final

      fileprivate var byte: UInt8 {
        switch self {
          case .message: crypto_secretstream_xchacha20poly1305_tag_message()
          case .push: crypto_secretstream_xchacha20poly1305_tag_push()
          case .rekey: crypto_secretstream_xchacha20poly1305_tag_rekey()
          case .final: crypto_secretstream_xchacha20poly1305_tag_final()
        }
      }

      fileprivate init?(byte: UInt8) {
        if byte == crypto_secretstream_xchacha20poly1305_tag_message() {
          self = .message
        } else if byte == crypto_secretstream_xchacha20poly1305_tag_push() {
          self = .push
        } else if byte == crypto_secretstream_xchacha20poly1305_tag_rekey() {
          self = .rekey
        } else if byte == crypto_secretstream_xchacha20poly1305_tag_final() {
          self = .final
        } else {
          return nil
        }
      }
    }

    /// A decrypted chunk and its authenticated tag.
    public struct Chunk: Hashable, Sendable {
      /// The plaintext data.
      public let data: Data

      /// The authenticated stream tag.
      public let tag: Tag
    }

    /// Stateful stream encryption. Instances must be used by one task at a time.
    public final class Encryptor {
      private let state: UnsafeMutablePointer<crypto_secretstream_xchacha20poly1305_state>
      private var isFinalized = false

      /// The public stream header to send before the first encrypted chunk.
      public let header: Header

      /// Starts a new encrypting stream.
      public init(key: Key) throws {
        try Sodium.initialize()
        guard let stateMemory = sodium_malloc(crypto_secretstream_xchacha20poly1305_statebytes())
        else {
          throw SodiumError.operationFailed
        }
        let statePointer = stateMemory.assumingMemoryBound(
          to: crypto_secretstream_xchacha20poly1305_state.self)
        var headerData = Data(count: Header.byteCount)
        let status = key.bytes.withUnsafeBytes { keyBytes in
          headerData.withUnsafeMutableBytes { headerBytes in
            crypto_secretstream_xchacha20poly1305_init_push(
              statePointer,
              headerBytes.bindMemory(to: UInt8.self).baseAddress!,
              keyBytes.bindMemory(to: UInt8.self).baseAddress!
            )
          }
        }
        guard status == 0 else {
          sodium_free(stateMemory)
          throw SodiumError.operationFailed
        }
        state = statePointer
        header = try Header(data: headerData)
      }

      deinit {
        sodium_free(state)
      }

      /// Encrypts and authenticates the next chunk.
      public func push<M: DataProtocol>(
        _ message: M,
        tag: Tag = .message,
        additionalData: Data = Data()
      ) throws -> Data {
        guard !isFinalized else { throw SodiumError.invalidState }
        let message = Data(message)
        var ciphertext = Data(count: message.count + SecretStream.overheadByteCount)
        var ciphertextCount: UInt64 = 0
        let status = withUnsafeBytePointer(to: message) { messagePointer, messageCount in
          withUnsafeBytePointer(to: additionalData) { additionalPointer, additionalCount in
            ciphertext.withUnsafeMutableBytes { ciphertextBytes in
              crypto_secretstream_xchacha20poly1305_push(
                state,
                ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
                &ciphertextCount,
                messagePointer,
                UInt64(messageCount),
                additionalPointer,
                UInt64(additionalCount),
                tag.byte
              )
            }
          }
        }
        guard status == 0, ciphertextCount == UInt64(ciphertext.count) else {
          throw SodiumError.operationFailed
        }
        if tag == .final { isFinalized = true }
        return ciphertext
      }

      /// Explicitly rotates the stream key before the next chunk.
      public func rekey() throws {
        guard !isFinalized else { throw SodiumError.invalidState }
        crypto_secretstream_xchacha20poly1305_rekey(state)
      }
    }

    /// Stateful stream decryption. Instances must be used by one task at a time.
    public final class Decryptor {
      private let state: UnsafeMutablePointer<crypto_secretstream_xchacha20poly1305_state>
      private var isFinalized = false

      /// Starts a decrypting stream using its public header.
      public init(key: Key, header: Header) throws {
        try Sodium.initialize()
        guard let stateMemory = sodium_malloc(crypto_secretstream_xchacha20poly1305_statebytes())
        else {
          throw SodiumError.operationFailed
        }
        state = stateMemory.assumingMemoryBound(
          to: crypto_secretstream_xchacha20poly1305_state.self)
        let status = key.bytes.withUnsafeBytes { keyBytes in
          header.data.withUnsafeBytes { headerBytes in
            crypto_secretstream_xchacha20poly1305_init_pull(
              state,
              headerBytes.bindMemory(to: UInt8.self).baseAddress!,
              keyBytes.bindMemory(to: UInt8.self).baseAddress!
            )
          }
        }
        guard status == 0 else {
          sodium_free(stateMemory)
          throw SodiumError.operationFailed
        }
      }

      deinit {
        sodium_free(state)
      }

      /// Authenticates and decrypts the next chunk.
      public func pull<C: DataProtocol>(
        _ ciphertext: C,
        additionalData: Data = Data()
      ) throws -> Chunk {
        guard !isFinalized else { throw SodiumError.invalidState }
        let ciphertext = Data(ciphertext)
        guard ciphertext.count >= SecretStream.overheadByteCount else {
          throw SodiumError.authenticationFailed
        }
        var message = Data(count: ciphertext.count - SecretStream.overheadByteCount)
        var messageCount: UInt64 = 0
        var tagByte: UInt8 = 0
        let status = ciphertext.withUnsafeBytes { ciphertextBytes in
          withUnsafeBytePointer(to: additionalData) { additionalPointer, additionalCount in
            withUnsafeMutableBytePointer(to: &message) { messagePointer, _ in
              crypto_secretstream_xchacha20poly1305_pull(
                state,
                messagePointer,
                &messageCount,
                &tagByte,
                ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
                UInt64(ciphertext.count),
                additionalPointer,
                UInt64(additionalCount)
              )
            }
          }
        }
        guard status == 0, messageCount == UInt64(message.count), let tag = Tag(byte: tagByte)
        else {
          throw SodiumError.authenticationFailed
        }
        if tag == .final { isFinalized = true }
        return Chunk(data: message, tag: tag)
      }

      /// Explicitly rotates the stream key before the next chunk.
      public func rekey() throws {
        guard !isFinalized else { throw SodiumError.invalidState }
        crypto_secretstream_xchacha20poly1305_rekey(state)
      }
    }

    /// Per-chunk authentication overhead.
    public static var overheadByteCount: Int {
      Int(crypto_secretstream_xchacha20poly1305_abytes())
    }
  }
}
