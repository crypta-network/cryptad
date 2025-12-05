package org.bitpedia.util;

import java.security.DigestException;
import org.bouncycastle.crypto.digests.TigerDigest;

/**
 * Standalone Tiger hash wrapper backed by BouncyCastle's {@link TigerDigest}.
 *
 * <p>This class supplies a compact, reusable facade for computing Tiger digests without relying on
 * {@link java.security.MessageDigest} inheritance. Callers typically construct a fresh instance,
 * stream data with the {@code update(...)} methods, and finish with one of the {@code digest(...)}
 * variants. Instances are <strong>not</strong> thread-safe; use separate instances per thread or
 * synchronize externally. The internal digest resets itself after {@code doFinal}, allowing a
 * single instance to be reused across multiple inputs while preserving deterministic 192-bit
 * outputs. Copying creates a new wrapper that preserves the current intermediate state so clients
 * can branch computations (e.g., prefix sharing) without reprocessing previously supplied bytes.
 *
 * <p>Responsibilities:
 *
 * <ul>
 *   <li>Expose MessageDigest-compatible operations for legacy code without direct inheritance.
 *   <li>Provide fixed-length (24-byte) Tiger hashes suitable for compatibility checksums.
 *   <li>Allow state cloning to checkpoint long-running streaming computations.
 * </ul>
 */
public final class Tiger {

  /** Fixed-size Tiger digest length in bytes (192 bits). */
  private static final int HASH_LENGTH = 24;

  private final TigerDigest digest;

  /** Creates a Tiger digest with a fresh internal {@link TigerDigest} instance. */
  public Tiger() {
    this.digest = new TigerDigest();
  }

  private Tiger(Tiger source) {
    this.digest = new TigerDigest(source.digest);
  }

  /**
   * Returns the fixed output size for the Tiger digest used by this wrapper.
   *
   * <p>The length is always 24 bytes (192 bits) regardless of the amount of data processed so far.
   * No internal state is mutated by this query.
   *
   * @return 24-byte output length for the Tiger algorithm implemented by this class
   */
  public int engineGetDigestLength() {
    return HASH_LENGTH;
  }

  /**
   * Resets the underlying digest to its initial state, discarding any accumulated input.
   *
   * <p>Use this to start a new hash computation without allocating a new instance. After calling
   * this method, subsequent {@code update(...)} calls begin a fresh message. The operation is not
   * thread-safe; synchronize externally if instances are shared.
   */
  public void engineReset() {
    digest.reset();
  }

  /**
   * Feeds a single byte into the current digest computation.
   *
   * <p>This is a low-overhead convenience for streaming scenarios. It may be invoked repeatedly in
   * tight loops; buffering and block processing are handled internally by the underlying {@link
   * TigerDigest}. The method mutates internal state and therefore must not be called concurrently
   * on the same instance.
   *
   * @param input the next message byte to incorporate into the hash
   */
  public void engineUpdate(byte input) {
    digest.update(input);
  }

  /**
   * Updates the digest with a slice of the provided buffer.
   *
   * <p>Validation mirrors the historical MessageDigest implementation: {@code input} must be
   * non-null, and {@code offset} and {@code len} must describe a valid subrange. No defensive copy
   * of the buffer is taken; callers retain ownership of the array. The underlying digest
   * accumulates bytes in the order supplied.
   *
   * @param input source array containing message bytes; must not be {@code null}
   * @param offset zero-based index of the first byte to consume; must reference a valid position
   * @param len number of bytes to read starting at {@code offset}; must keep within the array
   *     bounds
   * @throws NullPointerException if {@code input} is {@code null}
   * @throws ArrayIndexOutOfBoundsException if the specified range falls outside {@code input}
   */
  public void engineUpdate(byte[] input, int offset, int len) {
    if (input == null) {
      throw new NullPointerException("input");
    }
    if (offset < 0 || len < 0 || offset + len > input.length) {
      // Match historical behaviour of the previous implementation.
      throw new ArrayIndexOutOfBoundsException(offset);
    }
    digest.update(input, offset, len);
  }

  /**
   * Completes the current hash computation and returns the digest as a new byte array.
   *
   * <p>The internal {@link TigerDigest} resets after computing the 24-byte output, allowing the
   * same {@link Tiger} instance to process additional messages. Callers own the returned array and
   * may modify it without affecting future computations.
   *
   * @return newly allocated 24-byte array containing the computed Tiger hash
   */
  public byte[] engineDigest() {
    byte[] out = new byte[HASH_LENGTH];
    digest.doFinal(out, 0);
    return out;
  }

  /**
   * Completes the current hash computation and writes the digest into a caller-provided buffer.
   *
   * <p>The buffer must expose at least 24 writable bytes beginning at {@code offset}, and {@code
   * len} must be no smaller than the digest length. After completion, the internal digest resets so
   * the instance can be reused. The method returns the number of bytes written (always 24).
   *
   * @param buf destination array that receives the digest bytes; must have sufficient capacity
   * @param offset starting index in {@code buf} where the digest is written; must be non-negative
   * @param len number of bytes the caller is willing to accept; must be at least the digest length
   * @return number of digest bytes written to {@code buf}; always equals {@link
   *     #engineGetDigestLength()}
   * @throws DigestException if {@code len} is smaller than the digest or space is insufficient at
   *     the requested offset
   */
  public int engineDigest(byte[] buf, int offset, int len) throws DigestException {
    if (len < HASH_LENGTH) {
      throw new DigestException("partial digests not returned");
    }
    if (buf.length - offset < HASH_LENGTH) {
      throw new DigestException("insufficient space in output buffer to store the digest");
    }
    return digest.doFinal(buf, offset);
  }

  /**
   * Creates a copy of this {@link Tiger} instance with an independent internal state.
   *
   * <p>The returned instance contains the same intermediate digest state captured at the moment of
   * invocation, enabling callers to branch computations (for example, to reuse a shared prefix
   * while hashing multiple suffixes). Subsequent updates on either instance do not affect the
   * other.
   *
   * @return new {@link Tiger} sharing the current digest progress but with independent mutation
   */
  public Tiger copy() {
    return new Tiger(this);
  }

  // Convenience aliases mirroring MessageDigest APIs for existing callers.

  /**
   * Alias for {@link #engineGetDigestLength()} retaining MessageDigest-style naming.
   *
   * <p>Exposes the digest size for callers that previously relied on {@code MessageDigest}. The
   * value is constant and reflects the 192-bit Tiger output. This method performs no allocation and
   * leaves the digest state untouched.
   *
   * @return the fixed Tiger digest length in bytes, matching {@link #engineGetDigestLength()}
   */
  @SuppressWarnings("unused")
  public int getDigestLength() {
    return engineGetDigestLength();
  }

  /**
   * Convenience alias for {@link #engineReset()} following the MessageDigest API surface.
   *
   * <p>Use this when migrating code that called {@code MessageDigest.reset()}. It clears any
   * buffered input so a new message can be processed with the same {@link Tiger} instance. No value
   * is returned, and no output buffer is required.
   */
  public void reset() {
    engineReset();
  }

  /**
   * MessageDigest-style single-byte update that delegates to {@link #engineUpdate(byte)}.
   *
   * <p>Preferred for compatibility with existing digest code paths. This method mutates the digest
   * state and must not be invoked concurrently on the same instance without external
   * synchronization.
   *
   * @param input single byte to add to the message stream
   */
  public void update(byte input) {
    engineUpdate(input);
  }

  /**
   * Adds the entire provided buffer to the digest in a single call.
   *
   * <p>This is equivalent to invoking {@link #engineUpdate(byte[], int, int)} with an offset of
   * zero and a length equal to {@code input.length}. The array must be non-null; otherwise a {@link
   * NullPointerException} is thrown by the delegated call.
   *
   * @param input buffer containing the bytes to hash; ownership remains with the caller
   * @throws NullPointerException if {@code input} is {@code null}
   */
  public void update(byte[] input) {
    engineUpdate(input, 0, input.length);
  }

  /**
   * MessageDigest-style alias for {@link #engineUpdate(byte[], int, int)}.
   *
   * <p>Maintains behavior compatible with legacy call sites that expect range validation identical
   * to {@code MessageDigest}. The method does not copy the provided array and therefore relies on
   * the caller to preserve the data until processing completes.
   *
   * @param input byte array containing message data to incorporate; must not be {@code null}
   * @param offset starting index of the data slice to process; must be within array bounds
   * @param len number of bytes to process from {@code input}; must not exceed remaining length
   * @throws NullPointerException if {@code input} is {@code null}
   * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} describe an invalid
   *     range
   */
  public void update(byte[] input, int offset, int len) {
    engineUpdate(input, offset, len);
  }

  /**
   * Computes the digest for all data supplied so far and returns a new byte array with the result.
   *
   * <p>After completion, the internal digest state resets so this instance can be reused to hash a
   * new message. The returned array is exactly 24 bytes long and independent of future operations.
   *
   * @return newly allocated 24-byte digest representing the hashed message
   */
  public byte[] digest() {
    return engineDigest();
  }

  /**
   * Computes the digest for all accumulated data and stores it into a caller-provided buffer.
   *
   * <p>The buffer range must accommodate 24 bytes beginning at {@code offset}; {@code len} serves
   * as a guard to mirror the MessageDigest contract. The digest state resets after writing the
   * output so the instance can be reused. The returned integer equals the digest length.
   *
   * @param buf destination buffer to receive the computed digest bytes
   * @param offset index within {@code buf} at which writing begins; must be non-negative
   * @param len maximum number of bytes the caller expects to be written; must be at least 24
   * @return number of bytes written (always 24) to the provided buffer
   * @throws DigestException if {@code len} is too small or insufficient space exists at {@code
   *     offset}
   */
  public int digest(byte[] buf, int offset, int len) throws DigestException {
    return engineDigest(buf, offset, len);
  }
}
