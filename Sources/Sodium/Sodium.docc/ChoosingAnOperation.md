# Choosing an operation

Select the narrowest primitive that represents the relationship between participants.

## Symmetric encryption

Use ``Sodium/SecretBox`` when both parties already share one secret key. Never reuse a nonce with the same key. The default sealing API generates a random nonce and stores it alongside the ciphertext.

Use ``Sodium/AEAD/XChaCha20Poly1305`` when unencrypted metadata must be bound to the ciphertext. The recipient must supply the same associated data to decrypt it.

Use ``Sodium/SecretStream`` for ordered sequences, large inputs, or protocols that need explicit message boundaries and rekeying. A stream is stateful; preserve chunk order and stop after the final tag.

## Public-key encryption

Use authenticated ``Sodium/PublicKeyBox`` operations when both sender and recipient have key pairs and the recipient must authenticate the sender.

Use anonymous sealed boxes when only the recipient has a key pair and sender identity is not part of the cryptographic guarantee.

## Signing

Use ``Sodium/Signing`` when readers need to authenticate data without decrypting it. A signature does not hide its message.

Use ``Sodium/Authentication`` when all participants share one secret key and only those participants need to create and verify tags.

## Session and subkeys

Use ``Sodium/KeyExchange`` to establish directional receive and transmit keys between a client and server. Roles are part of the protocol and must agree on both sides.

Use ``Sodium/KeyDerivation`` to derive independent subkeys from one high-entropy root key. Assign a stable eight-byte context per application domain and a unique identifier per subkey.

## Password storage

Use ``Sodium/PasswordHash`` for human passwords. Do not replace it with a fast generic hash. Store the encoded hash string exactly as returned; it already includes the salt and resource parameters.

Use ``Sodium/PasswordHash/deriveKey(from:salt:byteCount:limits:algorithm:)`` only when a protocol needs key material derived from a password. Persist its public salt, limits, algorithm, and output size.
