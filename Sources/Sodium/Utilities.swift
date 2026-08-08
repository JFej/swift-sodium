import CSodium

#if canImport(FoundationEssentials)
import protocol FoundationEssentials.DataProtocol
import struct FoundationEssentials.Data
#else
import protocol Foundation.DataProtocol
import struct Foundation.Data
#endif

extension Sodium {
  /// Constant-time comparisons and binary text representations.
  public enum Utilities: Sendable {
    /// Base64 alphabets supported by libsodium.
    public enum Base64Variant: Sendable {
      /// Standard Base64 with padding.
      case original

      /// Standard Base64 without padding.
      case originalNoPadding

      /// URL-safe Base64 with padding.
      case urlSafe

      /// URL-safe Base64 without padding.
      case urlSafeNoPadding

      fileprivate var value: Int32 {
        switch self {
          case .original: sodium_base64_VARIANT_ORIGINAL
          case .originalNoPadding: sodium_base64_VARIANT_ORIGINAL_NO_PADDING
          case .urlSafe: sodium_base64_VARIANT_URLSAFE
          case .urlSafeNoPadding: sodium_base64_VARIANT_URLSAFE_NO_PADDING
        }
      }
    }

    /// Compares equal-length data without leaking the first differing position.
    public static func constantTimeEquals<L: DataProtocol, R: DataProtocol>(
      _ lhs: L,
      _ rhs: R
    ) -> Bool {
      let lhs = Data(lhs)
      let rhs = Data(rhs)
      guard lhs.count == rhs.count else { return false }
      guard !lhs.isEmpty else { return true }
      return lhs.withUnsafeBytes { lhsBytes in
        rhs.withUnsafeBytes { rhsBytes in
          sodium_memcmp(lhsBytes.baseAddress!, rhsBytes.baseAddress!, lhs.count) == 0
        }
      }
    }

    /// Returns a lowercase hexadecimal representation.
    public static func hexadecimal<D: DataProtocol>(_ data: D) -> String {
      let alphabet = Array("0123456789abcdef".utf8)
      var encoded = [UInt8]()
      encoded.reserveCapacity(data.count * 2)
      for byte in data {
        encoded.append(alphabet[Int(byte >> 4)])
        encoded.append(alphabet[Int(byte & 0x0f)])
      }
      return String(decoding: encoded, as: UTF8.self)
    }

    /// Decodes a hexadecimal representation.
    public static func data(hexadecimal string: String) throws -> Data {
      guard string.utf8.count.isMultiple(of: 2) else { throw SodiumError.invalidEncoding }
      var result = Data()
      result.reserveCapacity(string.utf8.count / 2)
      var index = string.startIndex
      while index < string.endIndex {
        let end = string.index(index, offsetBy: 2)
        guard let byte = UInt8(string[index..<end], radix: 16) else {
          throw SodiumError.invalidEncoding
        }
        result.append(byte)
        index = end
      }
      return result
    }

    /// Encodes data using a libsodium Base64 alphabet.
    public static func base64<D: DataProtocol>(
      _ data: D,
      variant: Base64Variant = .urlSafeNoPadding
    ) throws -> String {
      try Sodium.initialize()
      let data = Data(data)
      let capacity = sodium_base64_encoded_len(data.count, variant.value)
      var output = [CChar](repeating: 0, count: capacity)
      let encoded = withUnsafeBytePointer(to: data) { pointer, count in
        sodium_bin2base64(&output, capacity, pointer, count, variant.value)
      }
      guard encoded != nil else { throw SodiumError.operationFailed }
      return String(
        decoding: output.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    /// Decodes data using a libsodium Base64 alphabet.
    public static func data(
      base64 string: String,
      variant: Base64Variant = .urlSafeNoPadding
    ) throws -> Data {
      try Sodium.initialize()
      let encoded = Data(string.utf8)
      var output = Data(count: encoded.count * 3 / 4 + 3)
      var outputCount = 0
      let status = withUnsafeBytePointer(to: encoded) { encodedPointer, encodedCount in
        output.withUnsafeMutableBytes { outputBytes in
          sodium_base642bin(
            outputBytes.baseAddress!,
            outputBytes.count,
            encodedPointer,
            encodedCount,
            nil,
            &outputCount,
            nil,
            variant.value
          )
        }
      }
      guard status == 0 else { throw SodiumError.invalidEncoding }
      output.removeSubrange(outputCount..<output.count)
      return output
    }
  }
}
