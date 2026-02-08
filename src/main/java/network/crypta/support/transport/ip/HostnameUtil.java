package network.crypta.support.transport.ip;

import java.util.regex.Pattern;
import network.crypta.io.AddressIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Lightweight helpers for validating hostnames and, optionally, numeric IP literals.
 *
 * <p>Behavior
 *
 * <ul>
 *   <li>If {@code allowIPAddress} is {@code true}, numeric literals are accepted based on {@link
 *       AddressIdentifier} (IPv4 including abridged forms, IPv6 including abbreviated forms and
 *       optional percent scope IDs).
 *   <li>Otherwise, inputs are matched against a conservative ASCII hostname pattern intended to
 *       cover ACE/IDNA (Punycode) labels. The pattern requires at least one dot and a 2–6 letter
 *       TLD; single-label names such as {@code localhost} are rejected by design.
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
 * <p>Notes
 *
 * <ul>
 *   <li>Validation is purely syntactic; no DNS or network I/O occurs.
 *   <li>The class is stateless and thread-safe.
 * </ul>
 */
public class HostnameUtil {
  private static final Logger LOG = LoggerFactory.getLogger(HostnameUtil.class);
  // Dotted-quad shape only; numeric range (0–255) is enforced in code to keep the regex simple.
  // Leading zeros are allowed by design (e.g., 001, 000) for compatibility with historical input.
  private static final Pattern IPV4_DOTTED_SHAPE = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}$");

  private HostnameUtil() {}

  /**
   * Validates a hostname or (optionally) a numeric IP literal using conservative syntax rules.
   *
   * <p>This routine performs no name resolution or network I/O; it checks textual form only.
   *
   * @param hn candidate value; must not be {@code null}
   * @param allowIPAddress when {@code true}, IPv4/IPv6 literals are accepted using {@link
   *     AddressIdentifier}; when {@code false}, only DNS-like hostnames are allowed
   * @return {@code true} if the input is valid, according to the class rules; otherwise {@code
   *     false}
   * @throws NullPointerException if {@code hn} is {@code null}
   * @see AddressIdentifier#getAddressType(String, boolean)
   */
  public static boolean isValidHostname(String hn, boolean allowIPAddress) {
    if (allowIPAddress && isValidIPAddressLiteral(hn)) return true;
    // NOTE: Accepts ACE (Punycode) labels commonly produced by IDNA processing; this path is not
    //       covered by exhaustive tests here.
    if (!matchesHostnamePattern(hn)) {
      logRejectedHostname(hn, allowIPAddress);
      return false;
    }
    return true;
  }

  // --- Helpers ---------------------------------------------------------------

  /**
   * Detects IPv6 textual forms that end with an embedded IPv4 dotted-quad ("ls32" as {@code
   * IPv4address}), allowing abbreviated IPv6 via {@code ::} and an optional numeric percent scope
   * ID suffix.
   *
   * <p>Examples: {@code ::ffff:127.0.0.1}, {@code 2001:db8::ffff:192.0.2.1%1}.
   *
   * <p>Notes:
   *
   * <ul>
   *   <li>Bracketed forms like {@code [::1]} are intentionally not supported per class docs.
   *   <li>Validation is purely syntactic; no DNS lookups occur.
   * </ul>
   */
  private static boolean looksLikeIPv6WithEmbeddedIPv4(String s) {
    String addr = stripScopeAndRejectBracketed(s);
    if (addr == null) return false;

    int lastColon = addr.lastIndexOf(':');
    if (lastColon < 0) return false; // must contain ':' preceding the IPv4 tail
    String tail = addr.substring(lastColon + 1);
    if (!isStrictIPv4DottedQuad(tail)) return false;

    String head = addr.substring(0, lastColon);
    if (head.isEmpty()) return false; // must have at least one hextet or '::'

    if (!hasAtMostOneDoubleColon(addr)) return false;

    int hextets = countExplicitHextets(head);
    if (hextets < 0) return false;

    boolean hasDoubleColon = addr.contains("::");
    // For IPv4-embedded IPv6, there are 96 bits carried by hextets and 32 bits by the IPv4 tail.
    // Thus: at most 6 explicit hextets (or exactly 6 when no "::" compression is present).
    return hasDoubleColon ? hextets <= 6 : hextets == 6;
  }

  private static boolean isValidIPAddressLiteral(String hn) {
    // Enable trace logging to aid diagnosis when {@link AddressIdentifier} does not classify
    // certain IPv6 textual variants (e.g., "fe80::204:1234:dead:beef").
    AddressIdentifier.AddressType addressType = AddressIdentifier.getAddressType(hn, true);
    if (LOG.isTraceEnabled()) LOG.trace("Address type of '{}' appears to be '{}'", hn, addressType);
    // Treat only non-hostname types as immediate success. Compare the enum directly to avoid
    // string-name regressions if enum constant names change (e.g., OTHER vs. "Other").
    if (addressType != AddressIdentifier.AddressType.OTHER) {
      return true;
    }

    // Fallback: accept IPv6 literals that embed an IPv4 dotted-quad tail (e.g.,
    // ::ffff:192.0.2.1), which may not be recognized by AddressIdentifier. This preserves prior
    // behavior where these legitimate forms passed when IPs were allowed.
    return looksLikeIPv6WithEmbeddedIPv4(hn);
  }

  private static boolean matchesHostnamePattern(String hn) {
    return hn.matches("(?:[-!#$%&'*+\\\\/0-9=?A-Z^_`a-z{|}]++\\.)++[a-zA-Z]{2,6}");
  }

  private static void logRejectedHostname(String hn, boolean allowIPAddress) {
    if (LOG.isDebugEnabled())
      LOG.debug("Rejected {} candidate: '{}'", allowIPAddress ? "host/IP" : "hostname", hn);
  }

  private static String stripScopeAndRejectBracketed(String s) {
    if (s == null || s.isEmpty()) return null;
    if (s.indexOf('[') >= 0 || s.indexOf(']') >= 0) return null; // reject bracketed forms
    int pct = s.indexOf('%');
    if (pct < 0) return s;
    String scope = s.substring(pct + 1);
    if (!isValidScopeId(scope)) return null;
    return s.substring(0, pct);
  }

  private static boolean isValidScopeId(String scope) {
    // Accept numeric and common interface-name scopes (1–32 of [0-9A-Za-z._-])
    if (scope.isEmpty() || scope.length() > 32) return false;
    for (int i = 0; i < scope.length(); i++) {
      if (!isValidScopeChar(scope.charAt(i))) return false;
    }
    return true;
  }

  private static boolean isValidScopeChar(char c) {
    return (c >= '0' && c <= '9')
        || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z')
        || c == '.'
        || c == '_'
        || c == '-';
  }

  /**
   * Produces a noderef-friendly textual host for an {@link java.net.InetAddress}.
   *
   * <p>- For IPv4, returns the dotted-quad. - For IPv6, returns the literal; if a zone is present
   * and the JVM exposes a numeric scope ID, replaces the interface-name zone with the numeric ID
   * (e.g., "%eth0" -> "%3").
   */
  public static String toNoderefHost(java.net.InetAddress addr) {
    if (addr == null) return null;
    if (addr instanceof java.net.Inet6Address i6) {
      String s = i6.getHostAddress();
      int pct = s.indexOf('%');
      if (pct >= 0) {
        int scopeId = i6.getScopeId();
        if (scopeId > 0) {
          return s.substring(0, pct + 1) + scopeId;
        }
      }
      return s;
    }
    return addr.getHostAddress();
  }

  private static boolean hasAtMostOneDoubleColon(String addr) {
    int first = addr.indexOf("::");
    return first < 0 || addr.indexOf("::", first + 1) < 0;
  }

  private static int countExplicitHextets(String head) {
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
      if (part.isEmpty()) continue; // participates in '::' compression
      if (!isHextet(part)) return -1;
      hextets++;
      if (hextets > 6) return -1; // cannot exceed 6 before the IPv4 tail
    }
    return hextets;
  }

  private static boolean isHextet(String s) {
    if (s.isEmpty() || s.length() > 4) return false;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      boolean isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
      if (!isHex) return false;
    }
    return true;
  }

  private static boolean isStrictIPv4DottedQuad(String s) {
    if (!IPV4_DOTTED_SHAPE.matcher(s).matches()) return false;
    int start = 0;
    for (int part = 0; part < 4; part++) {
      int end = (part < 3) ? s.indexOf('.', start) : s.length();
      if (end <= start || end - start > 3) return false;
      int v = 0;
      for (int i = start; i < end; i++) {
        v = (v * 10) + (s.charAt(i) - '0');
      }
      if (v > 255) return false;
      start = end + 1;
    }
    return true;
  }
}
