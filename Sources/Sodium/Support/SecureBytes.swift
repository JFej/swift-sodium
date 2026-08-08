import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

final class SecureBytes: @unchecked Sendable {
  private var storage: [UInt8]

  init(_ bytes: [UInt8]) {
    storage = bytes
  }

  convenience init<D: DataProtocol>(_ data: D) {
    self.init(Array(data))
  }

  deinit {
    storage.withUnsafeMutableBytes { buffer in
      if let baseAddress = buffer.baseAddress {
        sodium_memzero(baseAddress, buffer.count)
      }
    }
  }

  var count: Int { storage.count }

  func withUnsafeBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) rethrows -> Result {
    try storage.withUnsafeBytes(body)
  }

}

func randomData(count: Int) throws -> Data {
  try Sodium.initialize()
  guard count > 0 else { return Data() }
  var data = Data(count: count)
  data.withUnsafeMutableBytes { bytes in
    randombytes_buf(bytes.baseAddress!, count)
  }
  return data
}

func withUnsafeBytePointer<Result>(
  to data: Data,
  _ body: (UnsafePointer<UInt8>, Int) throws -> Result
) rethrows -> Result {
  if data.isEmpty {
    var placeholder: UInt8 = 0
    return try withUnsafePointer(to: &placeholder) { pointer in
      try body(pointer, 0)
    }
  }
  return try data.withUnsafeBytes { bytes in
    try body(bytes.bindMemory(to: UInt8.self).baseAddress!, bytes.count)
  }
}

func withUnsafeMutableBytePointer<Result>(
  to data: inout Data,
  _ body: (UnsafeMutablePointer<UInt8>, Int) throws -> Result
) rethrows -> Result {
  if data.isEmpty {
    var placeholder: UInt8 = 0
    return try withUnsafeMutablePointer(to: &placeholder) { pointer in
      try body(pointer, 0)
    }
  }
  return try data.withUnsafeMutableBytes { bytes in
    try body(bytes.bindMemory(to: UInt8.self).baseAddress!, bytes.count)
  }
}
