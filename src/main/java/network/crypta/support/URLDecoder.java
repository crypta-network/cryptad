package network.crypta.support;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Decodes percent-encoded URL/URI segments using UTF-8.
 *
 * <p>This utility intentionally differs from {@link java.net.URLDecoder}:
 *
 * <ul>
 *   <li>It deals with raw percent-encoding and does <em>not</em> implement the {@code
 *       application/x-www-form-urlencoded} rules (for example, {@code '+'} is <b>not</b> treated as
 *       a space).
 *   <li>It always interprets bytes as UTF-8 when forming the resulting {@link String}.
 *   <li>It rejects malformed escapes (e.g., truncated sequences, non-hex digits) and the NUL byte
 *       escape {@code %00} by throwing {@link URLEncodedFormatException}.
 * </ul>
 *
 * <p>Typical usage is to decode individual URI components (path segments, query parameter names or
 * values) where percent-encoding represents UTF-8 bytes. Example: {@code
 * URLDecoder.decode("%E2%9C%93", false)} yields the check mark character (✓).
 *
 * <p>Thread-safety: This class is stateless and its methods are thread-safe.
 *
 * <p>See also {@link URLEncoder} for the paired encoder.
 *
 * @author <a href="http://www.doc.ic.ac.uk/~twh1/">Theodore Hong</a> Originally!
 */
public class URLDecoder {
  private URLDecoder() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Decodes percent-encoded sequences in {@code s} and returns the UTF-8 result.
   *
   * <p>The input is treated as a raw URI component where percent-encoding encodes individual bytes.
   * Non-{@code '%'} characters are copied as their UTF-8 bytes; {@code "%XX"} sequences are
   * converted to the corresponding byte, and the accumulated bytes are decoded as UTF-8 at the end.
   * This method does not treat {@code '+'} as a space and does not implement the {@code
   * application/x-www-form-urlencoded} rules.
   *
   * <p>Tolerance behavior: When {@code tolerant} is {@code true}, a malformed escape right where it
   * appears (two non-hex digits following {@code '%'}) is passed through literally <em>until the
   * first successful percent-decoding occurs</em>. After the first successful decode, subsequent
   * malformed escapes cause {@link URLEncodedFormatException}. When {@code tolerant} is {@code
   * false}, any malformed escape causes an exception. In all modes, {@code %00} is rejected.
   *
   * <p>Preconditions: {@code s} must be non-{@code null}.
   *
   * <p>Complexity: O(n) time and O(n) additional memory in the length of {@code s}.
   *
   * @param s string to decode; must not be {@code null}
   * @param tolerant whether to pass through malformed escapes until the first successful decode
   * @return decoded string, interpreted as UTF-8
   * @throws URLEncodedFormatException if an escape is truncated, contains non-hex digits after
   *     {@code '%'}, or encodes a NUL byte ({@code %00})
   * @throws NullPointerException if {@code s} is {@code null}
   */
  public static String decode(String s, boolean tolerant) throws URLEncodedFormatException {
    // Empty input short‑circuit to avoid allocating buffers.
    if (s.isEmpty()) return "";
    final int len = s.length();
    // Collect raw bytes (decoded and verbatim) and interpret them as UTF‑8 once at the end. This
    // ensures percent‑encoded multi‑byte characters are reconstructed correctly.
    final ByteArrayOutputStream decodedBytes = new ByteArrayOutputStream();
    boolean hasDecodedSomething = false;

    int i = 0;
    while (i < len) {
      char c = s.charAt(i);
      if (c != '%') {
        // Write the UTF‑8 bytes of the literal character.
        byte[] encoded = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
        decodedBytes.write(encoded, 0, encoded.length);
        i++;
      } else {
        Result r = handlePercent(s, i, decodedBytes, tolerant, hasDecodedSomething);
        hasDecodedSomething = hasDecodedSomething || r.decoded;
        i = r.nextIndex;
      }
    }

    return decodedBytes.toString(StandardCharsets.UTF_8);
  }

  private static Result handlePercent(
      String s,
      int i,
      ByteArrayOutputStream decodedBytes,
      boolean tolerant,
      boolean hasDecodedSomething)
      throws URLEncodedFormatException {
    int len = s.length();
    // Not enough characters remain for "%XX" — treat as malformed.
    if (i >= len - 2) {
      throw new URLEncodedFormatException(s);
    }

    String hexval = s.substring(i + 1, i + 3);
    try {
      long read = Fields.hexToLong(hexval);
      // Reject NUL byte to avoid embedding 0x00 in results.
      if (read == 0) {
        throw new URLEncodedFormatException("Can't encode 00");
      }
      decodedBytes.write((int) read);
      return new Result(i + 3, true);
    } catch (NumberFormatException _) {
      // Tolerate an apparent escape only until the first successful decode, to avoid silently
      // "fixing" mixed or partially encoded input.
      if (tolerant && !hasDecodedSomething) {
        byte[] buf = ('%' + hexval).getBytes(StandardCharsets.UTF_8);
        decodedBytes.write(buf, 0, buf.length);
        return new Result(i + 3, false);
      }
      throw new URLEncodedFormatException(
          "Not a two character hex % escape: " + hexval + " in " + s);
    }
  }

  // Result of handling a single "%.." sequence: where to continue and whether a byte was decoded.
  private record Result(int nextIndex, boolean decoded) {}
}
