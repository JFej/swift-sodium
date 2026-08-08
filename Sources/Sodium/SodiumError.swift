/// Errors produced by Sodium operations.
public enum SodiumError: Error, Equatable, Sendable {
  /// libsodium could not initialize its platform services.
  case initializationFailed

  /// A key had an unexpected number of bytes.
  case invalidKeyLength(expected: Int, actual: Int)

  /// A nonce had an unexpected number of bytes.
  case invalidNonceLength(expected: Int, actual: Int)

  /// A seed had an unexpected number of bytes.
  case invalidSeedLength(expected: Int, actual: Int)

  /// A fixed-width domain-separation context had an unexpected number of bytes.
  case invalidContextLength(expected: Int, actual: Int)

  /// A digest length was outside the algorithm's supported range.
  case invalidDigestLength(minimum: Int, maximum: Int, actual: Int)

  /// Text or binary data could not be decoded using the requested representation.
  case invalidEncoding

  /// A stateful operation was used after it had been finalized.
  case invalidState

  /// Ciphertext was malformed, truncated, or failed authentication.
  case authenticationFailed

  /// A signature did not authenticate the supplied message.
  case invalidSignature

  /// Password hashing failed, commonly because the requested memory limit was unavailable.
  case passwordHashingFailed

  /// An underlying cryptographic operation failed.
  case operationFailed
}
