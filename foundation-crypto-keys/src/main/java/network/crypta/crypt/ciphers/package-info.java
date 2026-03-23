/**
 * Low-level Rijndael block cipher primitives.
 *
 * <p>This package contains a compact, self-contained implementation of the Rijndael block cipher
 * (the algorithm family from which AES derives). It is retained primarily for interoperability with
 * legacy formats and protocols that historically used Rijndael with a 256-bit block size. New code
 * in Crypta should prefer modern AEAD constructions (for example, AES-GCM as used by {@link
 * network.crypta.crypt.AEADInputStream} and {@link network.crypta.crypt.AEADOutputStream}).
 *
 * <h2>What is provided</h2>
 *
 * <ul>
 *   <li>{@link network.crypta.crypt.ciphers.Rijndael}: a simple {@link
 *       network.crypta.crypt.BlockCipher} facade that exposes single-block encrypt/decrypt and
 *       publishes the selected JCA provider for {@code AES/CTR/NoPadding} when available.
 *   <li>{@link network.crypta.crypt.ciphers.RijndaelAlgorithm}: the optimized, table-driven core
 *       with static initialization of S-boxes/T-boxes and round keys.
 * </ul>
 *
 * <h2>Supported sizes</h2>
 *
 * <ul>
 *   <li>Keys: 128, 192, or 256 bits.
 *   <li>Blocks: 128 or 256 bits. The 192-bit block variant of Rijndael is not implemented.
 * </ul>
 *
 * AES corresponds to Rijndael with a 128-bit block size. A 256-bit block size is supported here
 * only for historical compatibility.
 *
 * <h2>Provider detection</h2>
 *
 * When the runtime permits 256-bit AES keys, {@link network.crypta.crypt.ciphers.Rijndael} attempts
 * to locate a {@code AES/CTR/NoPadding} implementation via JCA and may prefer Bouncy Castle if a
 * brief benchmark indicates it is faster. If detection fails (for example, due to key-size
 * restrictions), callers can fall back to the built-in Rijndael block primitives.
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * BlockCipher c = new Rijndael(256, 256); // key bits, block bits
 * c.initialize(keyBytes);
 * c.encipher(plainBlock, cipherBlock);
 * }</pre>
 *
 * All arrays must be exactly {@code blockSize/8} bytes long. Methods throw {@link
 * java.lang.IllegalArgumentException} when sizes do not match.
 *
 * <h2>Threading</h2>
 *
 * {@code RijndaelAlgorithm} methods are stateless after static initialization. The {@code Rijndael}
 * facade stores a computed key schedule per instance. Prefer one instance per thread or provide
 * external synchronization if instances are shared.
 *
 * <h2>Security notes</h2>
 *
 * These primitives do not provide authentication or integrity. Avoid introducing new uses in favor
 * of AEAD modes. In stream modes such as CTR, nonce/IV handling and integrity protection are the
 * caller's responsibility.
 */
package network.crypta.crypt.ciphers;
