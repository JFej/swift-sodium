# Key handling

Treat secret keys as capabilities rather than ordinary data.

## Recommendations

- Generate keys with their default initializer.
- Persist keys only in platform storage appropriate for secrets.
- Share public keys freely, but authenticate their owner through a separate trusted channel.
- Avoid exporting secret-key bytes unless an integration boundary requires it.
- Rotate a key immediately after suspected disclosure.
- Use separate keys for separate purposes. Prefer ``Sodium/KeyDerivation`` over reusing one root key directly.
- Store nonces and salts with ciphertext; they are public but required for decryption.

Secret key types expose `withUnsafeBytes` for narrowly scoped interoperability. The buffer is valid only for the closure's duration and must not be retained.

Secret-key types intentionally do not conform to `Hashable` or expose an unrestricted data representation. Public keys, nonces, salts, signatures, and ciphertext can be serialized normally.
