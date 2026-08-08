import Sodium
import Testing

import struct Foundation.Data

@Suite("Utilities")
struct UtilitiesTests {
  @Test("Constant-time equality handles equal, unequal, and differently sized data")
  func constantTimeEquality() {
    #expect(Sodium.Utilities.constantTimeEquals(Data([1, 2, 3]), Data([1, 2, 3])))
    #expect(!Sodium.Utilities.constantTimeEquals(Data([1, 2, 3]), Data([1, 2, 4])))
    #expect(!Sodium.Utilities.constantTimeEquals(Data([1, 2, 3]), Data([1, 2])))
  }

  @Test("Hexadecimal round trip")
  func hexadecimal() throws {
    let data = Data([0, 1, 127, 128, 254, 255])
    let encoded = Sodium.Utilities.hexadecimal(data)

    #expect(encoded == "00017f80feff")
    #expect(try Sodium.Utilities.data(hexadecimal: encoded) == data)
    #expect(throws: SodiumError.invalidEncoding) {
      try Sodium.Utilities.data(hexadecimal: "not hex")
    }
  }

  @Test(arguments: [
    Sodium.Utilities.Base64Variant.original,
    .originalNoPadding,
    .urlSafe,
    .urlSafeNoPadding,
  ])
  func base64(variant: Sodium.Utilities.Base64Variant) throws {
    let data = Data("Swift sodium + /".utf8)
    let encoded = try Sodium.Utilities.base64(data, variant: variant)

    #expect(try Sodium.Utilities.data(base64: encoded, variant: variant) == data)
  }
}
