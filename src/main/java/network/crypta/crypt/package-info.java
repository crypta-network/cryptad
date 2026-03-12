/**
 * Cryptographic primitives and helpers used by the Crypta node.
 *
 * <p>This package provides implementations and thin wrappers around the Java Cryptography
 * Architecture (JCA) and BouncyCastle to expose stable, provider-agnostic APIs and higher-level
 * utilities. It includes authenticated encryption streams, hashing and MAC helpers, key generation
 * and agreement utilities, and random sources.
 *
 * <p>Highlights:
 *
 * <ul>
 *   <li>Streaming AEAD using AES-GCM via {@link network.crypta.crypt.AEADInputStream} and {@link
 *       network.crypta.crypt.AEADOutputStream}. On-disk format uses a 16-byte written prefix where
 *       the first 12 bytes form the GCM nonce and the remaining 4 bytes are reserved, plus a
 *       16-byte authentication tag (total overhead: 32 bytes).
 *   <li>Digest/MAC utilities: {@link network.crypta.crypt.Hash}, {@link network.crypta.crypt.HMAC},
 *       and multi-hash streams ({@link network.crypta.crypt.MultiHashInputStream}, {@link
 *       network.crypta.crypt.MultiHashOutputStream}).
 *   <li>Asymmetric primitives and helpers: {@link network.crypta.crypt.ECDSA}, {@link
 *       network.crypta.crypt.ECDH}, and key utilities ({@link network.crypta.crypt.KeyGenUtils},
 *       {@link network.crypta.crypt.KeyType}).
 *   <li>Block cipher helpers: {@link network.crypta.crypt.BlockCipher} abstractions and {@link
 *       network.crypta.crypt.BlockCiphers} factory methods.
 *   <li>Errors surfaced as checked exceptions where appropriate: {@link
 *       network.crypta.crypt.CryptFormatException}, {@link
 *       network.crypta.crypt.UnsupportedCipherException}, and {@link
 *       network.crypta.crypt.UnsupportedTypeException}.
 * </ul>
 *
 * <p>Threading and usage notes:
 *
 * <ul>
 *   <li>Unless noted otherwise, types are not thread-safe. Create a fresh instance per use.
 *   <li>For AEAD streams, integrity is verified at end-of-stream. Always fully consume or close the
 *       stream and check for {@code IOException} to detect authentication failures.
 *   <li>Do not reuse nonces/IVs outside the provided stream formats; {@link
 *       network.crypta.crypt.AEADOutputStream} manages them for the on-disk format.
 * </ul>
 */
package network.crypta.crypt;
