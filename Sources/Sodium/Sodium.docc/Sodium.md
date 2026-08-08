# ``Sodium``

Safe, strongly typed access to libsodium cryptography.

## Overview

Use Sodium's high-level namespaces instead of calling the C module directly. Keys, nonces, signatures, and sealed boxes are distinct types, preventing accidental parameter substitution.

```swift
let key = try Sodium.SecretBox.Key()
let message = Data("Hello".utf8)
let sealedBox = try Sodium.SecretBox.seal(message, using: key)
let plaintext = try Sodium.SecretBox.open(sealedBox, using: key)
```

Sodium initializes the native library automatically. Secret keys keep their storage private and clear their owned buffer during deinitialization.

## Topics

### Symmetric encryption

- ``Sodium/SecretBox``
- ``Sodium/AEAD``
- ``Sodium/SecretStream``

### Public-key encryption

- ``Sodium/PublicKeyBox``

### Digital signatures

- ``Sodium/Signing``

### Message authentication

- ``Sodium/Authentication``

### Key establishment and derivation

- ``Sodium/KeyExchange``
- ``Sodium/KeyDerivation``

### Hashing

- ``Sodium/GenericHash``
- ``Sodium/PasswordHash``

### Randomness

- ``Sodium/Random``

### Encodings and comparison

- ``Sodium/Utilities``

### Errors and diagnostics

- ``SodiumError``
- ``Sodium/version``
- ``Sodium/initialize()``

### Guides

- <doc:ChoosingAnOperation>
- <doc:KeyHandling>
