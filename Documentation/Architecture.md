# Architecture

`swift-sodium` deliberately separates the stable C ABI from the evolving Swift API.

## CSodium

`CSodium` is a SwiftPM `staticLibrary` Artifact Bundle. One archive contains all target variants. Every variant contains a static libsodium library compiled from the same pinned upstream release. Shared public headers and a Clang module map expose the C API as the `CSodium` module.

## Sodium

`Sodium` is compiled from source with the consuming application's Swift compiler. It owns initialization, validation, memory handling, typed errors, and the public API. No Swift ABI is embedded in the Artifact Bundle.

The public implementation conditionally imports `FoundationEssentials` where the toolchain
provides it. Older compatible toolchains import only `Data` and `DataProtocol` from
Foundation. This keeps the API portable while avoiding localization and internationalization
components on size-sensitive WebAssembly targets.

`CSodium` is also exposed as a low-level library product. It is an interoperability escape hatch, not the default API: callers choosing it own buffer sizing, nonce discipline, return-code handling, and secret-memory lifetime.

## Dependency flow

```text
Application
    └── Sodium (Swift source)
            └── CSodium (multi-variant static-library Artifact Bundle)
                    └── libsodium
```

## Compatibility contract

All variants in a release must:

- come from the same libsodium source digest;
- pass the same known-answer vectors;
- expose the same headers and module map;
- be statically linked;
- contain no unexpected platform-library dependencies;
- produce compatible ciphertext and signatures.
