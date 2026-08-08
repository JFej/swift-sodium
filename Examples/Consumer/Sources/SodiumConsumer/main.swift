import Sodium

#if canImport(FoundationEssentials)
import struct FoundationEssentials.Data
#else
import struct Foundation.Data
#endif

let key = try Sodium.SecretBox.Key()
let message = Data("Artifact Bundle consumer".utf8)
let sealedBox = try Sodium.SecretBox.seal(message, using: key)
let plaintext = try Sodium.SecretBox.open(sealedBox, using: key)

guard plaintext == message else {
  fatalError("Sodium consumer round trip failed")
}

print("Sodium \(Sodium.version) consumer succeeded")
