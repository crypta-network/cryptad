/* @(#)SHA1.java	1.11 2004-04-26
 * This file was freely contributed to the LimeWire project and is covered
 * by its existing GPL licence, but it may be used individually as a public
 * domain implementation of a published algorithm (see below for references).
 * It was also freely contributed to the Bitzi public domain sources.
 * @author  Philippe Verdy
 */

/* Sun may wish to change the following package name, if integrating this
 * class in the Sun JCE Security Provider for Java 1.5 (code-named Tiger).
 *
 * You can include it in your own Security Provider by inserting
 * this property in your Provider derived class:
 * put("MessageDigest.SHA-1", "com.limegroup.gnutella.security.SHA1");
 */

package org.bitpedia.util;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-1 digest adapter backed by the JDK {@link MessageDigest} implementation.
 *
 * <p>This class preserves the public surface of the legacy Bitzi/LimeWire SHA-1 implementation
 * while delegating all cryptographic work to the platform provider. Create an instance, stream
 * bytes via {@link #update(byte)} or {@link #update(byte[], int, int)}, and call {@link #digest()}
 * to obtain the 20-byte result. A {@link #copy()} helper snapshots the current state so callers can
 * branch hashing flows without recomputing prefixes.
 *
 * <p>State is mutable and not thread-safe; coordinate access externally if sharing across threads.
 * The delegate is resolved once at construction using {@link MessageDigest#getInstance(String)} and
 * therefore respects installed security providers and policies. This wrapper adds minimal overhead
 * while avoiding duplicated crypto code and keeps behaviour aligned with the JDK's SHA-1, including
 * automatic reset after digesting.
 *
 * <ul>
 *   <li>Responsibilities: provide a stable wrapper API, enforce digest length, and expose state
 *       cloning via {@link #copy()}.
 *   <li>Notable behaviours: digest calls reset the instance; buffer bounds are validated before
 *       update operations; {@link #engineDigest(byte[], int, int)} refuses partial outputs.
 *   <li>Thread-safety: no internal locking—callers must serialize updates and digests.
 * </ul>
 *
 * @see MessageDigest
 */
@SuppressWarnings("java:S2257")
public final class Sha1 extends MessageDigest {

  /** SHA-1 digest length in bytes. */
  public static final int HASH_LENGTH = 20; // bytes == 160 bits

  private final MessageDigest delegate;

  /**
   * Creates a new SHA-1 digest with a clean initial state obtained from the platform provider.
   *
   * <p>The constructor resolves the {@code SHA-1} algorithm once and stores the resulting delegate.
   * The instance is immediately ready to accept updates without further initialization.
   */
  public Sha1() {
    this(newDelegate());
  }

  private Sha1(MessageDigest delegate) {
    super("SHA-1");
    this.delegate = delegate;
  }

  /**
   * Creates a copy of the current digest state.
   *
   * <p>The returned instance holds an independently cloned {@link MessageDigest} whose internal
   * state matches the source at the time of invocation. Subsequent updates or digests on either
   * instance do not affect the other, enabling branching hash computations without replaying input.
   *
   * @return a new {@link Sha1} whose digest state equals this instance yet diverges thereafter
   */
  public Sha1 copy() {
    return new Sha1(cloneDelegate(delegate));
  }

  @Override
  public Object clone() {
    return copy();
  }

  /**
   * Resets this digest to its initial, empty state.
   *
   * <p>All accumulated input is discarded. Use when reusing a single instance for multiple hashing
   * operations instead of allocating a new object.
   */
  @Override
  public void reset() {
    delegate.reset();
  }

  /**
   * Updates the digest with a single byte of message data.
   *
   * @param input next byte to incorporate; any value in the full byte range is accepted
   */
  @Override
  public void update(byte input) {
    delegate.update(input);
  }

  /**
   * Updates the digest with all bytes from the supplied array.
   *
   * @param input buffer containing the next message chunk; must not be {@code null} but may be
   *     empty
   */
  @Override
  public void update(byte[] input) {
    delegate.update(input);
  }

  /**
   * Updates the digest with a slice of the supplied array.
   *
   * @param input source buffer containing message bytes; must not be {@code null}
   * @param offset zero-based index of the first byte to read; must be within {@code input} bounds
   * @param len number of bytes to consume starting at {@code offset}; must be non-negative and fit
   *     inside the buffer
   * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} describe an invalid
   *     range within {@code input}
   */
  @Override
  public void update(byte[] input, int offset, int len) {
    delegate.update(input, offset, len);
  }

  /**
   * Compatibility wrapper mirroring {@link #update(byte)} for SPI-style callers.
   *
   * @param input single byte of message data to incorporate; accepts all byte values
   */
  @SuppressWarnings("unused")
  @Override
  public void engineUpdate(byte input) {
    update(input);
  }

  /**
   * Compatibility wrapper mirroring {@link #update(byte[], int, int)} for SPI-style callers.
   *
   * @param input source buffer containing message bytes; must not be {@code null}
   * @param offset starting index of the slice to consume; validated against {@code input.length}
   * @param len number of bytes to process from {@code input} beginning at {@code offset}
   * @throws ArrayIndexOutOfBoundsException if the specified slice exceeds buffer bounds
   */
  @Override
  public void engineUpdate(byte[] input, int offset, int len) {
    if (offset < 0 || len < 0 || offset + len > input.length) {
      throw new ArrayIndexOutOfBoundsException(offset);
    }
    update(input, offset, len);
  }

  /**
   * Completes the hash computation and returns the 20-byte digest.
   *
   * <p>After completion the instance resets to its initial state. The returned array is newly
   * allocated and owned by the caller; later updates operate on the reset state.
   *
   * @return a fresh 20-byte array containing the SHA-1 digest of all data supplied so far
   */
  @Override
  public byte[] digest() {
    return delegate.digest();
  }

  /**
   * Completes the hash computation and writes the digest into a caller-provided buffer.
   *
   * <p>The digest length is fixed at {@link #HASH_LENGTH}. On success the instance resets to its
   * initial state. Only the designated region of the buffer is overwritten; other bytes are left
   * untouched.
   *
   * @param hashvalue destination array that will receive the digest bytes; must not be {@code null}
   * @param offset starting index in {@code hashvalue} where the first digest byte will be written
   * @param len number of bytes the caller has allocated for the digest; must be at least {@link
   *     #HASH_LENGTH}
   * @return the number of bytes written, always {@link #HASH_LENGTH} when successful
   * @throws DigestException if {@code len} is too small or insufficient room remains from {@code
   *     offset} to the end of {@code hashvalue}
   */
  @Override
  public int engineDigest(byte[] hashvalue, int offset, int len) throws DigestException {
    if (len < HASH_LENGTH) {
      throw new DigestException("partial digests not returned");
    }
    if (hashvalue.length - offset < HASH_LENGTH) {
      throw new DigestException("insufficient space in output buffer to store the digest");
    }
    int written = delegate.digest(hashvalue, offset, HASH_LENGTH);
    if (written != HASH_LENGTH) {
      throw new DigestException("unexpected digest length: " + written);
    }
    return written;
  }

  /**
   * Completes the hash computation and returns the digest in a newly allocated buffer.
   *
   * <p>Convenience wrapper around {@link #engineDigest(byte[], int, int)} that handles allocation
   * and checked exceptions. In the unlikely event of a {@link DigestException}, an empty array is
   * returned to mirror historical behaviour.
   *
   * @return a new array containing the 20-byte digest, or an empty array if digesting fails
   */
  @Override
  public byte[] engineDigest() {
    byte[] hashvalue = new byte[HASH_LENGTH];
    try {
      engineDigest(hashvalue, 0, HASH_LENGTH);
      return hashvalue;
    } catch (DigestException e) {
      return new byte[0];
    }
  }

  /**
   * Compatibility wrapper for legacy callers that used the {@code MessageDigestSpi} naming.
   *
   * <p>Delegates directly to {@link #reset()} to clear state.
   */
  @SuppressWarnings("unused")
  @Override
  public void engineReset() {
    reset();
  }

  /**
   * Returns the length, in bytes, of the digest produced by this implementation.
   *
   * @return {@link #HASH_LENGTH}, always {@code 20} for SHA-1
   */
  @Override
  protected int engineGetDigestLength() {
    return HASH_LENGTH;
  }

  @SuppressWarnings("java:S4790")
  private static MessageDigest newDelegate() {
    try {
      return MessageDigest.getInstance("SHA-1");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-1 MessageDigest not available", e);
    }
  }

  private static MessageDigest cloneDelegate(MessageDigest digest) {
    try {
      return (MessageDigest) digest.clone();
    } catch (CloneNotSupportedException e) {
      throw new IllegalStateException("SHA-1 MessageDigest is not cloneable", e);
    }
  }
}
