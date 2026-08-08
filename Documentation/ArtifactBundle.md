# Artifact Bundle

The release asset is named `CSodium.artifactbundle.zip`. It contains one `staticLibrary` artifact and a variant for each target triple.

## Variant matrix

The release workflow currently builds:

- `arm64-apple-macosx`, `x86_64-apple-macosx`
- Apple device and simulator triples for iOS, tvOS, watchOS, and visionOS
- `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`
- Android API 28 through 36 triples for `aarch64`, `armv7`, and `x86_64`
- `aarch64-unknown-windows-msvc`, `x86_64-unknown-windows-msvc`
- `wasm32-unknown-wasi`

The exact triples in `info.json` are the source of truth.

The release gate requires all 49 target triples. A locally assembled development bundle may intentionally contain only the host or selected cross-compilation variants.

## Release sequence

1. Build each platform family in an isolated GitHub-hosted runner.
2. Upload unsigned static-library variants as workflow artifacts.
3. Assemble one Artifact Bundle and validate its metadata.
4. Build and test a clean consumer package against the assembled bundle.
5. Calculate the SwiftPM checksum.
6. Update the release version and checksum in `Package.swift`.
7. Commit the release metadata, create the semantic-version tag, and upload the exact tested archive.

The release job never rebuilds an artifact after calculating its checksum.

CI executes the same Swift known-answer suite on native Apple, Linux, and Windows hosts.
Swift Testing currently qualifies Android and WebAssembly as build-only platforms, so those
jobs compile the complete test suite in addition to the consumer executable. Native runtime
execution will replace those compile gates when the upstream testing runtime supports it.
