import Sodium

#if canImport(FoundationEssentials)
import struct FoundationEssentials.Data
#else
import struct Foundation.Data
#endif

struct Benchmark {
  let name: String
  let byteCount: Int
  let iterations: Int
  let operation: () throws -> Void

  func run() throws {
    let clock = ContinuousClock()
    let duration = try clock.measure {
      for _ in 0..<iterations { try operation() }
    }
    let seconds =
      Double(duration.components.seconds)
      + Double(duration.components.attoseconds) / 1_000_000_000_000_000_000
    let mib = Double(byteCount * iterations) / 1_048_576
    let throughput = seconds > 0 ? mib / seconds : 0
    print("\(name): \(iterations) iterations, \(throughput) MiB/s")
  }
}

let payload = Data(repeating: 0xA5, count: 1_048_576)
let metadata = Data("benchmark-v1".utf8)
let secretBoxKey = try Sodium.SecretBox.Key()
let aeadKey = try Sodium.AEAD.XChaCha20Poly1305.Key()

let benchmarks = [
  Benchmark(name: "BLAKE2b-256", byteCount: payload.count, iterations: 64) {
    _ = try Sodium.GenericHash.hash(payload, byteCount: 32)
  },
  Benchmark(name: "SecretBox seal", byteCount: payload.count, iterations: 64) {
    _ = try Sodium.SecretBox.seal(payload, using: secretBoxKey)
  },
  Benchmark(name: "XChaCha20-Poly1305 seal", byteCount: payload.count, iterations: 64) {
    _ = try Sodium.AEAD.XChaCha20Poly1305.seal(
      payload,
      authenticating: metadata,
      using: aeadKey
    )
  },
]

for benchmark in benchmarks {
  try benchmark.run()
}
