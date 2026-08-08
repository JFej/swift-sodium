# Contributing

## Development

1. Install the toolchain with `mise install`.
2. Create the host Artifact Bundle with `mise run bootstrap`.
3. Run `mise run test` and `mise run lint`.
4. Add Swift Testing coverage for behavior changes.
5. Update DocC for public API changes.

Keep the Swift layer independent of platform APIs. Platform differences belong in the Artifact Bundle build scripts, not in the public API.

## API design

- Follow the Swift API Design Guidelines.
- Prefer domain-specific types over byte arrays.
- Use throwing APIs for recoverable failures.
- Never expose mutable secret-key storage.
- Avoid adding algorithms that libsodium intentionally keeps out of its high-level API.

## Pull requests

Use a focused title and explain compatibility or security implications. All required CI checks
must pass before merging.
