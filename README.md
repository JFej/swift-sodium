# swift-sodium

[![CI](https://github.com/JFej/swift-sodium/actions/workflows/ci.yml/badge.svg)](https://github.com/JFej/swift-sodium/actions/workflows/ci.yml)
[![Swift Package Index](https://img.shields.io/badge/Swift%20Package%20Index-DocC-orange)](https://swiftpackageindex.com/JFej/swift-sodium)
[![Swift 6.3+](https://img.shields.io/badge/Swift-6.3%2B-F05138.svg)](https://www.swift.org)

A safe, strongly typed Swift interface to [libsodium](https://libsodium.org) for Apple
platforms, Linux, Android, Windows, and WebAssembly/WASI.

The Swift API is distributed as source. The C implementation is distributed exclusively as one multi-variant `CSodium.artifactbundle`, containing statically linked libsodium builds for Apple platforms, Linux, Android, Windows, and WebAssembly/WASI. There is no source-build or XCFramework fallback.

## Requirements

- Swift 6.3 or newer
- Xcode 27 or newer for Apple platform development

## Installation

Add the package in `Package.swift`:

```swift
dependencies: [
  .package(url: "https://github.com/JFej/swift-sodium.git", from: "0.1.0")
]
```

Then add `Sodium` to the target dependencies:

```swift
.product(name: "Sodium", package: "swift-sodium")
```

## Example

```swift
import Sodium

let key = try Sodium.SecretBox.Key()
let sealedBox = try Sodium.SecretBox.seal(Data("Hello".utf8), using: key)
let plaintext = try Sodium.SecretBox.open(sealedBox, using: key)
```

The high-level API also includes XChaCha20-Poly1305 AEAD, authenticated streams,
digital signatures, message authentication, generic and password hashing, key
derivation, key exchange, secure randomness, and encoding utilities. Import the
`CSodium` product only when interoperating with a libsodium operation that does
not yet have a typed Swift wrapper.

## Architecture

The package has two layers:

- `CSodium`: one static-library Artifact Bundle with a variant for every supported target triple.
- `Sodium`: a source-distributed Swift API with typed keys, nonces, signatures, sealed boxes, and errors.

Secret material is represented by dedicated non-`Hashable` types. Raw access is
scoped to `withUnsafeBytes` closures, and owned buffers are cleared when released.

Only the C ABI crosses the binary boundary. No precompiled Swift module is distributed, avoiding Swift compiler and runtime ABI coupling.

## Local development

Build the host variant before invoking SwiftPM directly:

```sh
mise install
mise run bootstrap
mise run test
mise run check:sanitizers
mise run check:upstream
```

`bootstrap` downloads the pinned libsodium source archive, verifies its SHA-256 digest,
compiles a static host library, and creates the ignored local
`Artifacts/CSodium.artifactbundle`.

Performance benchmarks are opt-in and run separately from correctness tests:

```sh
mise run benchmark
```

## Supported variants

| Family | Architectures |
| --- | --- |
| Apple | arm64 and x86_64 where supported; device and simulator variants |
| Linux | aarch64, x86_64 |
| Android | aarch64, armv7, x86_64 |
| Windows | aarch64, x86_64 MSVC |
| WASI | wasm32 |

See [Artifact Bundle](Documentation/ArtifactBundle.md) for the complete triple matrix and release process.

## Security

Cryptographic software deserves careful review. See [SECURITY.md](SECURITY.md) before reporting a vulnerability. The package does not invent cryptographic primitives; it provides Swift types around audited libsodium operations.

## License

`swift-sodium` is available under the MIT License. libsodium is distributed under the ISC License; its license and notices are included in every release artifact.
