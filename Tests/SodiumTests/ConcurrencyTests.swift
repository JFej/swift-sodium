import Sodium
import Testing

import struct Foundation.Data

@Suite("Concurrency")
struct ConcurrencyTests {
  @Test("Initialization is safe under contention")
  func concurrentInitialization() async throws {
    try await withThrowingTaskGroup(of: Void.self) { group in
      for _ in 0..<256 {
        group.addTask { try Sodium.initialize() }
      }
      try await group.waitForAll()
    }
  }

  @Test("Independent stateless operations are safe in parallel")
  func concurrentOperations() async throws {
    let key = try Sodium.AEAD.XChaCha20Poly1305.Key()
    let signingKeys = try Sodium.Signing.KeyPair()

    try await withThrowingTaskGroup(of: Void.self) { group in
      for index in 0..<128 {
        group.addTask {
          let message = Data("message-\(index)".utf8)
          let additionalData = Data("task-\(index)".utf8)
          let sealed = try Sodium.AEAD.XChaCha20Poly1305.seal(
            message,
            authenticating: additionalData,
            using: key
          )
          let opened = try Sodium.AEAD.XChaCha20Poly1305.open(
            sealed,
            authenticating: additionalData,
            using: key
          )
          let signature = try Sodium.Signing.sign(message, using: signingKeys.secretKey)
          guard opened == message,
            Sodium.Signing.isValid(
              signature,
              authenticating: message,
              using: signingKeys.publicKey
            )
          else {
            throw SodiumError.operationFailed
          }
        }
      }
      try await group.waitForAll()
    }
  }
}
