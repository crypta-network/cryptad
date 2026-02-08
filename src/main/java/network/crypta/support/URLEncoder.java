package network.crypta.support;

import java.nio.charset.StandardCharsets;

/**
 * Encodes strings for use in URIs. Note that this is <b>NOT</b> the same as java.net.URLEncoder,
 * which encodes strings to application/x-www-urlencoded. This is much closer to what java.net.URI
 * does. We don't turn spaces into +'s, and we allow through non-ascii characters unless told not
 * to.
 */
public class URLEncoder {
  // Moved here from FProxy by amphibian
  /**
   * Uppercase-named constant for safe URL characters to satisfy constant naming conventions.
   *
   * <p>Keep {@code safeURLCharacters} as a non-final alias for backward source/binary compatibility
   * across the codebase.
   */
  static final String SAFE_URL_CHARACTERS =
      "*-_./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

  // Backward-compatibility alias used widely across the codebase and tests.
  static String safeURLCharacters = SAFE_URL_CHARACTERS;

  public static String getSafeURLCharacters() {
    return safeURLCharacters;
  }

  public static String encode(String url, String force, boolean ascii) {
    return encode(url, force, ascii, "");
  }

  /**
   * Encode a string for inclusion in a URI.
   *
   * @param url String to encode
   * @param force List of characters (in the form of a string) which must be encoded as well as the
   *     built-in.
   * @param ascii If true, encode all foreign letters, if false, leave them as is. Set to true if
   *     you are passing to something that needs ASCII (e.g., HTTP headers), set to false if you are
   *     using in an HTML page.
   * @return Encoded version of string
   */
  public static String encode(String url, String force, boolean ascii, String extraSafeChars) {
    StringBuilder enc = new StringBuilder(url.length());
    for (int i = 0; i < url.length(); ++i) {
      char c = url.charAt(i);
      if (isPassThrough(c, force, ascii, extraSafeChars)) {
        enc.append(c);
      } else {
        appendUtf8PercentEncoded(enc, c);
      }
    }
    return enc.toString();
  }

  private static boolean isPassThrough(char c, String force, boolean ascii, String extraSafeChars) {
    boolean inSafeSet = safeURLCharacters.indexOf(c) >= 0 || extraSafeChars.indexOf(c) >= 0;
    boolean unicodeAllowed =
        !ascii
            && c >= 128
            && Character.isDefined(c)
            && !Character.isISOControl(c)
            && !Character.isSpaceChar(c);
    boolean notForced = (force == null || force.indexOf(c) < 0);
    return (inSafeSet || unicodeAllowed) && notForced;
  }

  private static void appendUtf8PercentEncoded(StringBuilder enc, char c) {
    for (byte b : String.valueOf(c).getBytes(StandardCharsets.UTF_8)) {
      int x = b & 0xFF;
      if (x < 16) enc.append("%0");
      else enc.append('%');
      enc.append(Integer.toHexString(x));
    }
  }

  /**
   * Encode a string for inclusion in a URI.
   *
   * @param url String to encode
   * @param ascii If true, encode all foreign letters, if false, leave them as is. Set to true if
   *     you are passing to something that needs ASCII (e.g., HTTP headers), set to false if you are
   *     using in an HTML page.
   * @return Encoded version of string
   */
  public static String encode(String url, boolean ascii) {
    return encode(url, null, ascii);
  }

  private URLEncoder() {}
}
