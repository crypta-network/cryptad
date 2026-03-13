package org.bitpedia.util.hash;

import java.nio.ByteBuffer;
import java.security.DigestException;

/**
 * Minimal streaming hash contract used by custom digest implementations such as Tiger Tree and
 * ED2K.
 *
 * <p>Provides the subset of the {@link java.security.MessageDigest} API required by callers without
 * tying implementations to the JCA SPI. Implementations are stateful and not thread-safe; callers
 * should use one instance per hashing operation.
 */
public interface StreamingHash {

  /** Returns the fixed digest length, in bytes, produced by this hash. */
  int getDigestLength();

  /** Updates the digest with a single byte. */
  void update(byte input);

  /** Updates the digest with a slice of the provided array. */
  void update(byte[] input, int offset, int len);

  /** Updates the digest with the full contents of the provided array. */
  default void update(byte[] input) {
    if (input == null) {
      throw new NullPointerException("input");
    }
    update(input, 0, input.length);
  }

  /** Updates the digest with the remaining bytes of the provided buffer, advancing its position. */
  void update(ByteBuffer input);

  /**
   * Completes the digest computation and returns the result, resetting internal state for reuse.
   *
   * @return newly allocated array containing the hash bytes
   */
  byte[] digest();

  /**
   * Completes the digest computation and writes the result into the supplied buffer.
   *
   * @return number of bytes written (always equals {@link #getDigestLength()})
   * @throws DigestException if {@code len} is smaller than the digest length
   */
  int digest(byte[] buf, int offset, int len) throws DigestException;

  /** Resets the internal state to begin a new digest computation. */
  void reset();
}
