import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

extension Sodium {
  /// Ed25519 digital signatures.
  public enum Signing: Sendable {
    /// A public signature-verification key.
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
      public static var byteCount: Int { Int(crypto_sign_publickeybytes()) }

      /// The key's raw representation.
      public var dataRepresentation: Data { data }
    }

    /// A secret signing key.
    public struct SecretKey: Sendable {
      private let bytes: SecureBytes

      /// Creates a secret key from raw bytes.
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
      public static var byteCount: Int { Int(crypto_sign_secretkeybytes()) }

      /// Provides temporary read-only access to raw key bytes.
      public func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
      ) rethrows -> Result {
        try bytes.withUnsafeBytes(body)
      }
    }

    /// A deterministic signing-key seed.
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
      public static var byteCount: Int { Int(crypto_sign_seedbytes()) }
    }

    /// A matching signing and verification key pair.
    public struct KeyPair: Sendable {
      /// The shareable verification key.
      public let publicKey: PublicKey

      /// The private signing key.
      public let secretKey: SecretKey

      /// Generates a random key pair.
      public init() throws {
        try Sodium.initialize()
        var publicBytes = [UInt8](repeating: 0, count: PublicKey.byteCount)
        var secretBytes = [UInt8](repeating: 0, count: SecretKey.byteCount)
        guard crypto_sign_keypair(&publicBytes, &secretBytes) == 0 else {
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
          crypto_sign_seed_keypair(
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

    /// A detached Ed25519 signature.
    public struct Signature: Hashable, Sendable {
      let data: Data

      /// Creates a signature from raw bytes.
      public init<D: DataProtocol>(data: D) throws {
        let data = Data(data)
        guard data.count == Self.byteCount else {
          throw SodiumError.invalidSignature
        }
        self.data = data
      }

      /// The detached-signature size.
      public static var byteCount: Int { Int(crypto_sign_bytes()) }

      /// The signature's raw representation.
      public var dataRepresentation: Data { data }
    }

    /// A message with its Ed25519 signature attached.
    public struct SignedMessage: Hashable, Sendable {
      /// `signature || message`, as produced by libsodium.
      public let combined: Data

      /// Creates an attached signed message from its combined representation.
      public init<D: DataProtocol>(combined: D) throws {
        let combined = Data(combined)
        guard combined.count >= Signature.byteCount else { throw SodiumError.invalidSignature }
        self.combined = combined
      }
    }

    /// Creates a detached signature.
    public static func sign<D: DataProtocol>(
      _ message: D,
      using key: SecretKey
    ) throws -> Signature {
      try Sodium.initialize()
      let message = Data(message)
      var signature = Data(count: Signature.byteCount)
      var signatureLength: UInt64 = 0
      let status = key.withUnsafeBytes { keyBytes in
        withUnsafeBytePointer(to: message) { messagePointer, _ in
          signature.withUnsafeMutableBytes { signatureBytes in
            crypto_sign_detached(
              signatureBytes.bindMemory(to: UInt8.self).baseAddress!,
              &signatureLength,
              messagePointer,
              UInt64(message.count),
              keyBytes.bindMemory(to: UInt8.self).baseAddress!
            )
          }
        }
      }
      guard status == 0, signatureLength == UInt64(Signature.byteCount) else {
        throw SodiumError.operationFailed
      }
      return try Signature(data: signature)
    }

    /// Verifies a detached signature.
    public static func verify<D: DataProtocol>(
      _ signature: Signature,
      authenticating message: D,
      using key: PublicKey
    ) throws {
      try Sodium.initialize()
      let message = Data(message)
      let status = key.data.withUnsafeBytes { keyBytes in
        signature.data.withUnsafeBytes { signatureBytes in
          withUnsafeBytePointer(to: message) { messagePointer, _ in
            crypto_sign_verify_detached(
              signatureBytes.bindMemory(to: UInt8.self).baseAddress!,
              messagePointer,
              UInt64(message.count),
              keyBytes.bindMemory(to: UInt8.self).baseAddress!
            )
          }
        }
      }
      guard status == 0 else { throw SodiumError.invalidSignature }
    }

    /// Returns whether a detached signature is valid.
    public static func isValid<D: DataProtocol>(
      _ signature: Signature,
      authenticating message: D,
      using key: PublicKey
    ) -> Bool {
      (try? verify(signature, authenticating: message, using: key)) != nil
    }

    /// Signs a message and returns the attached `signature || message` representation.
    public static func signAttached<D: DataProtocol>(
      _ message: D,
      using key: SecretKey
    ) throws -> SignedMessage {
      try Sodium.initialize()
      let message = Data(message)
      var signed = Data(count: message.count + Signature.byteCount)
      var signedLength: UInt64 = 0
      let status = key.withUnsafeBytes { keyBytes in
        withUnsafeBytePointer(to: message) { messagePointer, _ in
          signed.withUnsafeMutableBytes { signedBytes in
            crypto_sign(
              signedBytes.bindMemory(to: UInt8.self).baseAddress!,
              &signedLength,
              messagePointer,
              UInt64(message.count),
              keyBytes.bindMemory(to: UInt8.self).baseAddress!
            )
          }
        }
      }
      guard status == 0, signedLength == UInt64(signed.count) else {
        throw SodiumError.operationFailed
      }
      return try SignedMessage(combined: signed)
    }

    /// Verifies an attached signature and returns the original message.
    public static func open(_ signedMessage: SignedMessage, using key: PublicKey) throws -> Data {
      try Sodium.initialize()
      var message = Data(count: signedMessage.combined.count - Signature.byteCount)
      var messageLength: UInt64 = 0
      let status = key.data.withUnsafeBytes { keyBytes in
        signedMessage.combined.withUnsafeBytes { signedBytes in
          withUnsafeMutableBytePointer(to: &message) { messagePointer, _ in
            crypto_sign_open(
              messagePointer,
              &messageLength,
              signedBytes.bindMemory(to: UInt8.self).baseAddress!,
              UInt64(signedMessage.combined.count),
              keyBytes.bindMemory(to: UInt8.self).baseAddress!
            )
          }
        }
      }
      guard status == 0, messageLength == UInt64(message.count) else {
        throw SodiumError.invalidSignature
      }
      return message
    }
  }
}
