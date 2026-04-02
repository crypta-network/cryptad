package network.crypta.support;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

/**
 * Pre-encodes characters that are illegal in a URI by applying percent-encoding with UTF-8.
 *
 * <p>This utility accepts "dirty" inputs (for example, strings containing spaces) and converts them
 * into a form suitable for {@link URI#URI(String)} without altering characters that are already
 * allowed in a URI or are already percent-encoded.
 *
 * <p>It is <em>not</em> equivalent to {@link java.net.URLEncoder}. That class implements the HTML
 * form encoding scheme ({@code application/x-www-form-urlencoded}) and is inappropriate for general
 * URI encoding.
 *
 * <p>Thread-safety: All methods are stateless and thread-safe.
 */
public class URIPreEncoder {

  // Utility class: prevent instantiation.
  private URIPreEncoder() {}

  /**
   * Characters that pass through {@link #encode(String)} unchanged.
   *
   * <p>The set includes {@code '%'} to avoid double-encoding existing percent-escape sequences and
   * {@code '#'} to preserve fragment anchors. The remainder corresponds to commonly accepted
   * unreserved and sub-delimiter characters for URIs.
   */
  public static final String ALLOWED_CHARS =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-!.~'()*,;:$&+=?/@%#";

  /**
   * Returns a copy of the input where every character not present in {@link #ALLOWED_CHARS} is
   * replaced with its percent-encoded UTF-8 byte sequence.
   *
   * <p>Existing percent-encoded sequences are left untouched because {@code '%'} is in the allowed
   * set. No normalization of path segments or query parameters is performed.
   *
   * @param s input to encode; must not be {@code null}
   * @return the encoded string, suitable for use in {@link URI#URI(String)}
   * @throws NullPointerException if {@code s} is {@code null}
   */
  public static String encode(String s) {
    StringBuilder output = new StringBuilder(s.length() * 2);
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (ALLOWED_CHARS.indexOf(c) >= 0) {
        output.append(c);
      } else {
        String tmp = String.valueOf(c);
        for (byte u : tmp.getBytes(StandardCharsets.UTF_8)) {
          int x = u & 0xff;
          output.append('%');
          if (x < 16) output.append('0');
          output.append(Integer.toHexString(x));
        }
      }
    }
    return output.toString();
  }

  /**
   * Creates a {@link URI} from a possibly "dirty" string by first applying {@link #encode(String)}.
   *
   * <p>This method does not validate or normalize beyond what {@link URI} performs. Inputs that are
   * invalid even after encoding will result in an exception.
   *
   * @param s input string that may contain characters requiring percent-encoding; must not be
   *     {@code null}
   * @return a URI constructed from the encoded representation of {@code s}
   * @throws URISyntaxException if {@code s} does not represent a valid URI after encoding
   * @throws NullPointerException if {@code s} is {@code null}
   */
  public static URI encodeURI(String s) throws URISyntaxException {
    return new URI(encode(s));
  }
}
