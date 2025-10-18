package network.crypta.support.transport.ip;

import network.crypta.io.AddressIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Lightweight hostname validation helpers.
 *
 * <p>Behavior
 *
 * <ul>
 *   <li>If {@code allowIPAddress} is {@code true}, numeric IP literals are accepted based on {@link
 *       AddressIdentifier} (IPv4 including abridged forms, IPv6 including abbreviated forms and
 *       optional percent scope IDs).
 *   <li>Otherwise, hostnames are checked with a conservative ASCII pattern intended to cover
 *       ACE/IDNA (Punycode) labels. It requires at least one dot and a 2–6 letter TLD. Single-label
 *       names such as {@code localhost} are rejected by design.
 * </ul>
 *
 * <p>Limitations
 *
 * <ul>
 *   <li>This is not a full IDNA implementation; Unicode hostnames must be supplied in ACE
 *       (Punycode) form.
 *   <li>Bracketed IPv6 forms (e.g., {@code [::1]}) are not recognized; supply raw literals.
 *   <li>TLDs longer than 6 ASCII letters are not accepted.
 * </ul>
 *
 * <p>This class is stateless and thread-safe.
 */
public class HostnameUtil {
  private static final Logger LOG = LoggerFactory.getLogger(HostnameUtil.class);

  private HostnameUtil() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Validates a host name or (optionally) a numeric IP literal.
   *
   * @param hn the candidate value; must not be {@code null}
   * @param allowIPAddress when {@code true}, IPv4/IPv6 literals are accepted using {@link
   *     AddressIdentifier}; when {@code false}, only DNS-like hostnames are allowed.
   * @return {@code true} if the input is valid according to the rules above; otherwise {@code
   *     false}
   * @throws NullPointerException if {@code hn} is {@code null}
   * @see AddressIdentifier#getAddressType(String, boolean)
   */
  public static boolean isValidHostname(String hn, boolean allowIPAddress) {
    if (allowIPAddress) {
      // debugging log messages because AddressIdentifier doesn't appear to handle all IPv6 literals
      // correctly, such as "fe80::204:1234:dead:beef"
      AddressIdentifier.AddressType addressType = AddressIdentifier.getAddressType(hn, true);
      if (LOG.isTraceEnabled())
        LOG.trace("Address type of '{}' appears to be '{}'", hn, addressType);
      // Treat only non-hostname types as immediate success. Compare the enum directly to avoid
      // string-name regressions when enum constant names change (e.g., OTHER vs "Other").
      if (addressType != AddressIdentifier.AddressType.OTHER) {
        return true;
      }

      // Fallback: Accept IPv6 literals that embed an IPv4 dotted-quad tail (e.g.,
      // ::ffff:192.0.2.1),
      // which AddressIdentifier currently does not recognize. This keeps prior behavior where these
      // legitimate forms passed when IPs were allowed.
      if (looksLikeIPv6WithEmbeddedIPv4(hn)) {
        return true;
      }
    }
    // NOTE: It is believed that this code supports PUNYCODE based
    //       ASCII Compatible Encoding (ACE) IDNA labels as
    //       described in RFC3490.  Such an assertion has not been
    //       thoroughly tested.
    if (!hn.matches("(?:[-!#$%&'*+\\\\/0-9=?A-Z^_`a-z{|}]++\\.)++[a-zA-Z]{2,6}")) {
      LOG.warn("Failed to match {} as a hostname or IPv4/IPv6 IP address", hn);
      return false;
    }
    return true;
  }

  // --- Helpers ---------------------------------------------------------------

  /**
   * Detects IPv6 textual forms that end with an embedded IPv4 dotted-quad ("ls32" as IPv4address),
   * allowing abbreviated IPv6 via "::" and an optional percent scope ID suffix, e.g.
   * "::ffff:127.0.0.1" or "2001:db8::ffff:192.0.2.1%1".
   *
   * <p>Notes - Bracketed forms like "[::1]" are intentionally not supported per class docs. - This
   * routine validates purely syntactically without any DNS lookups.
   */
  private static boolean looksLikeIPv6WithEmbeddedIPv4(String s) {
    if (s == null || s.isEmpty()) return false;
    if (s.indexOf('[') >= 0 || s.indexOf(']') >= 0) return false; // no bracketed forms

    // Optional percent scope ID ("%<digits>") — accept only when trailing and numeric.
    String addr = s;
    int pct = s.indexOf('%');
    if (pct >= 0) {
      String scope = s.substring(pct + 1);
      if (scope.isEmpty() || scope.length() > 3) return false;
      for (int i = 0; i < scope.length(); i++)
        if (!Character.isDigit(scope.charAt(i))) return false;
      addr = s.substring(0, pct);
    }

    int lastColon = addr.lastIndexOf(':');
    if (lastColon < 0) return false; // must contain ':' preceding the IPv4 tail
    String tail = addr.substring(lastColon + 1);
    if (!isStrictIPv4DottedQuad(tail)) return false;

    String head = addr.substring(0, lastColon);
    if (head.isEmpty()) return false; // must have at least one hextet or '::'

    // Validate there is at most one "::" sequence. Detect on the full address (pre-tail) so
    // inputs like "::192.0.2.1" still register the double-colon even though "head" would be ":".
    int dcFirst = addr.indexOf("::");
    // Reject any second occurrence of "::", including overlapping forms like ":::".
    if (dcFirst >= 0 && addr.indexOf("::", dcFirst + 1) >= 0) return false;

    // Count explicit hextets (1..4 hex digits). When no "::" is present, there must be exactly
    // 6 hextets before the IPv4 tail (the tail counts as two hextets). When "::" is present, the
    // explicit hextet count must be <= 6 (the compression fills the remainder).
    int hextets = 0;
    int start = 0;
    while (start <= head.length()) {
      int next = head.indexOf(':', start);
      String part;
      if (next < 0) {
        part = head.substring(start);
        start = head.length() + 1;
      } else {
        part = head.substring(start, next);
        start = next + 1;
      }
      if (part.isEmpty()) {
        // empty part participates in a '::' compression; skip counting
        continue;
      }
      if (!isHextet(part)) return false;
      hextets++;
      if (hextets > 6) return false; // cannot exceed 6 before the IPv4 tail
    }

    boolean hasDoubleColon = dcFirst >= 0;
    return hasDoubleColon ? hextets <= 6 : hextets == 6;
  }

  private static boolean isHextet(String s) {
    if (s.length() < 1 || s.length() > 4) return false;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      boolean isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
      if (!isHex) return false;
    }
    return true;
  }

  private static boolean isStrictIPv4DottedQuad(String s) {
    int dots = 0;
    int val = -1; // -1 indicates not in a number yet
    int digits = 0;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '.') {
        if (val < 0 || digits == 0) return false;
        if (val > 255) return false;
        dots++;
        val = -1;
        digits = 0;
        continue;
      }
      if (c < '0' || c > '9') return false;
      int d = c - '0';
      val = (val < 0 ? d : (val * 10 + d));
      if (++digits > 3) return false;
    }
    if (dots != 3) return false;
    if (val < 0 || val > 255) return false;
    return true;
  }
}
