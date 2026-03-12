/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: Md5Handler.java,v 1.2 2006/07/14 04:58:39 gojomo Exp $
 */
package org.bitpedia.collider.core;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Incremental MD5 digest calculator used by the Bitcollider core utilities.
 *
 * <p>This handler wraps {@link MessageDigest} to provide a lightweight lifecycle of {@code
 * analyzeInit()} → {@code analyzeUpdate(...)} → {@code analyzeFinal()} that mirrors other hash
 * handlers in the package. Callers typically allocate one instance per hashing task, invoke {@link
 * #analyzeInit()} once, stream one or more buffers through the update methods, and finish with
 * {@link #analyzeFinal()} to obtain the 16-byte MD5 output.
 *
 * <p>The instance holds mutable digest state and is <strong>not</strong> thread-safe; share it only
 * within a single thread or guard external access. MD5 is maintained solely for compatibility with
 * legacy Bitprints and content descriptors and should not be relied upon for modern security
 * guarantees.
 *
 * <ul>
 *   <li>Provides both incremental and static one-shot helper methods.
 *   <li>Accepts caller-managed buffers without allocating temporary copies.
 *   <li>Returns a fresh digest byte array on every {@link #analyzeFinal()} invocation.
 * </ul>
 *
 * <pre>{@code
 * Md5Handler handler = new Md5Handler();
 * handler.analyzeInit();
 * handler.analyzeUpdate(buffer, buffer.length);
 * byte[] md5 = handler.analyzeFinal();
 * }</pre>
 */
public class Md5Handler {

  private MessageDigest digest;

  /**
   * Creates a new handler with no initialized digest state.
   *
   * <p>The instance begins in an inert state until {@link #analyzeInit()} is invoked, allowing
   * callers to set up the handler and then feed data incrementally. Construction itself performs no
   * allocation beyond the object shell, which keeps repeated uses inexpensive when handlers are
   * short-lived.
   */
  public Md5Handler() {
    // Intentionally empty: construction defers digest allocation until analyzeInit() is called.
  }

  /**
   * Initializes the internal MD5 {@link MessageDigest} instance prior to accepting data.
   *
   * <p>This method must be called exactly once per hashing lifecycle before any {@code
   * analyzeUpdate(...)} calls. Reusing the same {@code Md5Handler} for multiple inputs is supported
   * by invoking this initializer again after a previous {@link #analyzeFinal()}.
   */
  @SuppressWarnings("java:S4790")
  public void analyzeInit() {
    try {
      digest = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException _) {
      // Never happens - MD5 always exists
    }
  }

  /**
   * Updates the digest with the first {@code bufLen} bytes from the provided buffer.
   *
   * <p>Use this overload when the relevant data begins at index zero. The handler must already be
   * initialized via {@link #analyzeInit()}; otherwise a {@link NullPointerException} is thrown by
   * the underlying digest. No temporary copies are created, so caller-managed buffers remain
   * untouched.
   *
   * @param buf byte array containing source data; must be non-null and sized for {@code bufLen}.
   * @param bufLen number of bytes to read starting at offset {@code 0}; must satisfy {@code 0 <=
   *     bufLen <= buf.length}.
   */
  public void analyzeUpdate(byte[] buf, int bufLen) {

    digest.update(buf, 0, bufLen);
  }

  /**
   * Updates the digest with {@code bufLen} bytes beginning at the specified offset.
   *
   * <p>This overload supports hashing a slice of a larger buffer without copying. The handler must
   * have been initialized first; otherwise the underlying {@link MessageDigest} will raise a {@link
   * NullPointerException}. It is useful when multiple adjacent ranges from a single byte array need
   * to be hashed independently.
   *
   * @param buf byte array containing source data; must be non-null and large enough for the range.
   * @param ofs zero-based starting index within {@code buf} from which hashing begins.
   * @param bufLen number of bytes to consume from {@code buf} starting at {@code ofs}; must not
   *     exceed the remaining array length.
   */
  public void analyzeUpdate(byte[] buf, int ofs, int bufLen) {

    digest.update(buf, ofs, bufLen);
  }

  /**
   * Completes the digest computation and returns the MD5 hash bytes.
   *
   * <p>After calling this method, the underlying {@link MessageDigest} resets per its contract,
   * allowing the handler to be reinitialized for a new input stream. The returned array is a fresh
   * 16-byte value that the caller may freely modify. Invoking this method without prior updates
   * produces the MD5 digest for an empty input.
   *
   * @return new byte array containing the final 128-bit MD5 result for the accumulated input.
   */
  public byte[] analyzeFinal() {

    return digest.digest();
  }

  /**
   * Computes the MD5 digest of the first {@code len} bytes in the supplied buffer.
   *
   * <p>This convenience method wraps the incremental lifecycle for callers that already have the
   * entire payload in a single array. It does not allocate intermediate buffers and returns a new
   * digest array for each invocation. It is equivalent to constructing a handler, initializing it,
   * and issuing one update covering the desired prefix.
   *
   * @param buffer source byte array containing the content to hash; must be non-null.
   * @param len number of bytes from the start of {@code buffer} to include; must satisfy {@code 0
   *     <= len <= buffer.length}.
   * @return fresh byte array with the 16-byte MD5 digest of the selected prefix.
   */
  public static byte[] md5(byte[] buffer, int len) {

    Md5Handler md5Handler = new Md5Handler();
    md5Handler.analyzeInit();
    md5Handler.analyzeUpdate(buffer, len);
    return md5Handler.analyzeFinal();
  }

  /**
   * Computes the MD5 digest of a contiguous range within the supplied buffer.
   *
   * <p>This overload hashes {@code len} bytes beginning at {@code ofs}, enabling callers to reuse
   * larger shared buffers without copying. Each call constructs a new handler instance and returns
   * a fresh digest array. It matches the semantics of the incremental API without requiring callers
   * to track handler instances across call sites.
   *
   * @param buffer source byte array containing the content to hash; must be non-null.
   * @param ofs zero-based offset in {@code buffer} marking the first byte to include.
   * @param len number of bytes to hash starting at {@code ofs}; must not exceed the available tail
   *     of the array.
   * @return new byte array with the 16-byte MD5 digest for the requested slice of the buffer.
   */
  public static byte[] md5(byte[] buffer, int ofs, int len) {

    Md5Handler md5Handler = new Md5Handler();
    md5Handler.analyzeInit();
    md5Handler.analyzeUpdate(buffer, ofs, len);
    return md5Handler.analyzeFinal();
  }
}
