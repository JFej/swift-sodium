import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

extension Sodium {
  /// Public-key authenticated encryption using Curve25519 and XSalsa20-Poly1305.
  public enum PublicKeyBox: Sendable {
    /// A public encryption key.
    public struct PublicKey: Hashable, Sendable {
      let data: Data

      /// Creates a public key from its raw representation.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidKeyLength(expected: Self.byteCount, actual: data.count)
        }
        self.data = data
      }

      /// The required public-key size.
      public static var byteCount: Int { Int(crypto_box_publickeybytes()) }

      /// The key's raw representation.
      public var dataRepresentation: Data { data }
    }

    /// A secret encryption key.
    public struct SecretKey: Sendable {
      private let bytes: SecureBytes

      /// Creates a secret key from its raw representation.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidKeyLength(expected: Self.byteCount, actual: data.count)
        }
        bytes = SecureBytes(data)
      }

      init(bytes: [UInt8]) {
        self.bytes = SecureBytes(bytes)
      }

      /// The required secret-key size.
      public static var byteCount: Int { Int(crypto_box_secretkeybytes()) }

      /// Provides temporary read-only access to the raw key bytes.
      public func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
      ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
      }
    }

    /// A deterministic key-generation seed.
    public struct Seed: Sendable {
      fileprivate let bytes: SecureBytes

      /// Generates a random seed.
      public init() throws {
        bytes = SecureBytes(try randomData(count: Self.byteCount))
      }

      /// Creates a seed from raw bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidSeedLength(expected: Self.byteCount, actual: data.count)
        }
        bytes = SecureBytes(data)
      }

      /// The required seed size.
      public static var byteCount: Int { Int(crypto_box_seedbytes()) }
    }

    /// A matching public and secret key pair.
    public struct KeyPair: Sendable {
      /// The shareable public key.
      public let publicKey: PublicKey

      /// The private secret key.
      public let secretKey: SecretKey

      /// Generates a random key pair.
      public init() throws {
        try Sodium.initialize()
        var publicBytes = [UInt8](repeating: 0, count: PublicKey.byteCount)
        var secretBytes = [UInt8](repeating: 0, count: SecretKey.byteCount)
        guard crypto_box_keypair(&publicBytes, &secretBytes) == 0 else {
          throw SodiumError.operationFailed
        }
        publicKey = try PublicKey(data: publicBytes)
        secretKey = SecretKey(bytes: secretBytes)
        secretBytes.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
      }

      /// Derives a deterministic key pair from a seed.
      public init(seed: Seed) throws {
        try Sodium.initialize()
        var publicBytes = [UInt8](repeating: 0, count: PublicKey.byteCount)
        var secretBytes = [UInt8](repeating: 0, count: SecretKey.byteCount)
        let status = seed.bytes.withUnsafeBytes { seedBytes in
          crypto_box_seed_keypair(
            &publicBytes,
            &secretBytes,
            seedBytes.bindMemory(to: UInt8.self).baseAddress!
          )
        }
        guard status == 0 else { throw SodiumError.operationFailed }
        publicKey = try PublicKey(data: publicBytes)
        secretKey = SecretKey(bytes: secretBytes)
        secretBytes.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
      }
    }

    /// A unique public nonce for authenticated encryption.
    public struct Nonce: Hashable, Sendable {
      let data: Data

      /// Generates a random nonce.
      public init() throws {
        data = try randomData(count: Self.byteCount)
      }

      /// Creates a nonce from raw bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidNonceLength(expected: Self.byteCount, actual: data.count)
        }
        self.data = data
      }

      /// The required nonce size.
      public static var byteCount: Int { Int(crypto_box_noncebytes()) }

      /// The nonce's raw representation.
      public var dataRepresentation: Data { data }
    }

    /// Authenticated ciphertext and its nonce.
    public struct SealedBox: Hashable, Sendable {
      /// The public nonce.
      public let nonce: Nonce

      /// The authenticated ciphertext.
      public let ciphertext: Data

      /// Creates a sealed box from validated components.
      public init(nonce: Nonce, ciphertext: Data) throws {
        guard ciphertext.count >= PublicKeyBox.authenticationTagByteCount else {
          throw SodiumError.authenticationFailed
        }
        self.nonce = nonce
        self.ciphertext = ciphertext
      }

      /// Creates a sealed box from `nonce || authenticatedCiphertext`.
      public init<D: DataProtocol>(combined: D) throws {
        let combined = Data(combined)
        let minimum = Nonce.byteCount + PublicKeyBox.authenticationTagByteCount
        guard combined.count >= minimum else { throw SodiumError.authenticationFailed }
        nonce = try Nonce(data: combined.prefix(Nonce.byteCount))
        ciphertext = Data(combined.dropFirst(Nonce.byteCount))
      }

      /// `nonce || authenticatedCiphertext`.
      public var combined: Data { nonce.dataRepresentation + ciphertext }
    }

    /// Anonymous ciphertext created for one recipient.
    public struct AnonymousSealedBox: Hashable, Sendable {
      /// The raw libsodium sealed-box representation.
      public let combined: Data

      /// Creates an anonymous sealed box from its raw representation.
      public init<D: DataProtocol>(combined: D) throws {
        let combined = Data(combined)
        guard combined.count >= PublicKeyBox.anonymousOverheadByteCount else {
          throw SodiumError.authenticationFailed
        }
        self.combined = combined
      }
    }

    /// The authentication tag size for authenticated boxes.
    public static var authenticationTagByteCount: Int { Int(crypto_box_macbytes()) }

    /// The overhead added by an anonymous sealed box.
    public static var anonymousOverheadByteCount: Int { Int(crypto_box_sealbytes()) }

    /// Encrypts for a recipient and authenticates the sender.
    public static func seal<D: DataProtocol>(
      _ message: D,
      to recipient: PublicKey,
      authenticatedBy sender: SecretKey,
      nonce: Nonce? = nil
    ) throws -> SealedBox {
      try Sodium.initialize()
      let nonce = try nonce ?? Nonce()
      let message = Data(message)
      var ciphertext = Data(count: message.count + authenticationTagByteCount)

      let status = sender.withUnsafeBytes { senderBytes in
        recipient.data.withUnsafeBytes { recipientBytes in
          nonce.data.withUnsafeBytes { nonceBytes in
            withUnsafeBytePointer(to: message) { messagePointer, _ in
              ciphertext.withUnsafeMutableBytes { ciphertextBytes in
                crypto_box_easy(
                  ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
                  messagePointer,
                  UInt64(message.count),
                  nonceBytes.bindMemory(to: UInt8.self).baseAddress!,
                  recipientBytes.bindMemory(to: UInt8.self).baseAddress!,
                  senderBytes.bindMemory(to: UInt8.self).baseAddress!
                )
              }
            }
          }
        }
      }

      guard status == 0 else { throw SodiumError.operationFailed }
      return try SealedBox(nonce: nonce, ciphertext: ciphertext)
    }

    /// Authenticates a sender and decrypts a sealed box.
    public static func open(
      _ sealedBox: SealedBox,
      from sender: PublicKey,
      using recipient: SecretKey
    ) throws -> Data {
      try Sodium.initialize()
      guard sealedBox.ciphertext.count >= authenticationTagByteCount else {
        throw SodiumError.authenticationFailed
      }
      var message = Data(count: sealedBox.ciphertext.count - authenticationTagByteCount)

      let status = recipient.withUnsafeBytes { recipientBytes in
        sender.data.withUnsafeBytes { senderBytes in
          sealedBox.nonce.data.withUnsafeBytes { nonceBytes in
            sealedBox.ciphertext.withUnsafeBytes { ciphertextBytes in
              withUnsafeMutableBytePointer(to: &message) { messagePointer, _ in
                crypto_box_open_easy(
                  messagePointer,
                  ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
                  UInt64(sealedBox.ciphertext.count),
                  nonceBytes.bindMemory(to: UInt8.self).baseAddress!,
                  senderBytes.bindMemory(to: UInt8.self).baseAddress!,
                  recipientBytes.bindMemory(to: UInt8.self).baseAddress!
                )
              }
            }
          }
        }
      }

      guard status == 0 else { throw SodiumError.authenticationFailed }
      return message
    }

    /// Encrypts a message anonymously for a recipient.
    public static func sealAnonymous<D: DataProtocol>(
      _ message: D,
      to recipient: PublicKey
    ) throws -> AnonymousSealedBox {
      try Sodium.initialize()
      let message = Data(message)
      var ciphertext = Data(count: message.count + anonymousOverheadByteCount)
      let status = recipient.data.withUnsafeBytes { recipientBytes in
        withUnsafeBytePointer(to: message) { messagePointer, _ in
          ciphertext.withUnsafeMutableBytes { ciphertextBytes in
            crypto_box_seal(
              ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
              messagePointer,
              UInt64(message.count),
              recipientBytes.bindMemory(to: UInt8.self).baseAddress!
            )
          }
        }
      }
      guard status == 0 else { throw SodiumError.operationFailed }
      return try AnonymousSealedBox(combined: ciphertext)
    }

    /// Decrypts an anonymous sealed box.
    public static func openAnonymous(
      _ sealedBox: AnonymousSealedBox,
      using recipient: KeyPair
    ) throws -> Data {
      try Sodium.initialize()
      guard sealedBox.combined.count >= anonymousOverheadByteCount else {
        throw SodiumError.authenticationFailed
      }
      var message = Data(count: sealedBox.combined.count - anonymousOverheadByteCount)
      let status = recipient.secretKey.withUnsafeBytes { secretBytes in
        recipient.publicKey.data.withUnsafeBytes { publicBytes in
          sealedBox.combined.withUnsafeBytes { ciphertextBytes in
            withUnsafeMutableBytePointer(to: &message) { messagePointer, _ in
              crypto_box_seal_open(
                messagePointer,
                ciphertextBytes.bindMemory(to: UInt8.self).baseAddress!,
                UInt64(sealedBox.combined.count),
                publicBytes.bindMemory(to: UInt8.self).baseAddress!,
                secretBytes.bindMemory(to: UInt8.self).baseAddress!
              )
            }
          }
        }
      }
      guard status == 0 else { throw SodiumError.authenticationFailed }
      return message
    }
  }
}
