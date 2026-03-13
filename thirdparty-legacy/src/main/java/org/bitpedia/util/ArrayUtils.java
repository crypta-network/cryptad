/* (PD) 2006 The Bitzi Corporation
 * Please see http://bitzi.com/publicdomain for more info.
 *
 * $Id: ArrayUtils.java,v 1.2 2006/07/14 04:58:39 gojomo Exp $
 */
package org.bitpedia.util;

/**
 * Utility methods for converting byte values and ranges into lowercase hexadecimal strings.
 *
 * <p>This helper centralizes common encoding routines used by legacy Bitpedia code that relies on
 * compact, deterministic hex output for logging, identifiers, and serialization. Methods here do
 * not mutate shared state, allocate only local buffers, and avoid additional dependencies so they
 * remain safe to call from performance-sensitive or security-sensitive paths. Callers are expected
 * to pass valid offsets and lengths; the methods assume pre-validated input to keep the
 * implementation lightweight. Output always uses lowercase characters and zero-pads single-digit
 * values to two hex digits to preserve fixed-width formatting.
 *
 * <ul>
 *   <li>Stateless and thread-safe because all data is local to each invocation.
 *   <li>Best suited for small buffers and identifiers where readability matters more than
 *       streaming.
 *   <li>Intentionally minimal API surface to preserve backward compatibility with existing
 *       consumers.
 * </ul>
 *
 * @see #byteToHex(byte)
 * @see #byteArrayToHex(byte[], int, int)
 */
public class ArrayUtils {

  /**
   * Prevents instantiation because this class only provides static utility methods and maintains no
   * state.
   */
  private ArrayUtils() {}

  /**
   * Converts a single byte to a two-character, zero-padded lowercase hexadecimal string.
   *
   * <p>The byte is treated as an unsigned value in the range {@code 0} to {@code 255}. The result
   * always contains exactly two characters so that callers can safely concatenate multiple outputs
   * without additional padding logic. No allocation other than the internal string creation is
   * performed, making the method suitable for frequent use in logging or simple serialization
   * tasks.
   *
   * @param b the byte value to convert; interpreted unsigned so values map to {@code 00}–{@code ff}
   *     deterministically
   * @return a two-character lowercase hexadecimal representation of the supplied byte, never {@code
   *     null} or empty
   */
  public static String byteToHex(byte b) {

    return Integer.toString((b & 0xFF) + 0x100, 16).substring(1);
  }

  /**
   * Converts a contiguous range of a byte array into a lowercase hexadecimal string.
   *
   * <p>The slice defined by {@code offset} and {@code len} is copied into a newly allocated string
   * whose length is exactly {@code len * 2}. Callers must supply bounds that fall within the array;
   * this method performs no explicit range checks and will propagate any resulting {@link
   * ArrayIndexOutOfBoundsException}. An empty range produces an empty string, which callers can use
   * as a safe sentinel value. The method is thread-safe because it uses only local variables and
   * does not mutate the provided array.
   *
   * @param b the source byte array holding the data to encode; must not be {@code null}
   * @param offset zero-based starting index of the first byte to encode; must be within the array
   *     bounds
   * @param len number of bytes to encode starting at {@code offset}; must be non-negative and
   *     selected so {@code offset + len} does not exceed {@code b.length}
   * @return a lowercase hexadecimal string representing the requested slice; length equals {@code
   *     len * 2}
   */
  public static String byteArrayToHex(byte[] b, int offset, int len) {

    StringBuilder buf = new StringBuilder();

    for (int i = offset; i < offset + len; i++) {
      buf.append(byteToHex(b[i]));
    }

    return buf.toString();
  }
}
