package network.crypta.io;

import java.util.regex.Pattern;

/**
 * Identifies numeric IP address literals.
 *
 * <p>The detector recognizes the following textual forms and treats the input as a whole-string
 * match (when used with {@link java.util.regex.Matcher#matches()}):
 *
 * <ul>
 *   <li>IPv4 dotted-decimal with four octets (a.b.c.d)
 *   <li>IPv4 "abridged" forms with one or two missing octets (a.b.c or a.b)
 *   <li>IPv6 standard notation with hex words (a:b:c:d:e:f:g:h), case-insensitive
 *   <li>IPv6 compressed forms (for example, a::b:c:d:e)
 * </ul>
 *
 * <p>The implementation relies on precompiled {@link Pattern} instances and is thread-safe. Pattern
 * sources intentionally use ASCII-only digits for IPv4 in order to avoid matching non-ASCII digits
 * under Unicode-aware regex engines.
 *
 * @author David Roden &lt;droden@gmail.com&gt;
 * @version $Id$
 */
public class AddressIdentifier {
  /**
   * Precompiled regex for IPv4 dotted-decimal literals, including the common "abridged" variants
   * with fewer than four octets. Intended for whole-input matching via {@link
   * java.util.regex.Matcher#matches()} (anchors are not embedded in the pattern).
   *
   * <p>Digits are restricted to ASCII. See {@link #IPV4_BYTE_REGEX_ASCII} for rationale.
   */
  public static final Pattern ipv4Pattern;

  /**
   * Precompiled, case-insensitive regex for IPv6 textual representation without a scope ID. It
   * supports full and compressed forms. Intended for whole-input matching via {@link
   * java.util.regex.Matcher#matches()}.
   */
  public static final Pattern ipv6Pattern;

  /**
   * Like {@link #ipv6Pattern} but allows an optional percent scope ID suffix (for example, {@code
   * fe80::1%2} or {@code fe80::1%eth0}). Intended for whole-input matching via {@link
   * java.util.regex.Matcher#matches()}.
   */
  public static final Pattern ipv6PatternWithPercentScopeID;

  /**
   * Precompiled, case-insensitive regex for detecting IPv6 ISATAP addresses as defined in
   * RFC&nbsp;4214. The pattern permits an optional percent scope ID. Use via {@link
   * java.util.regex.Matcher#matches()} and prefer the convenience method {@link
   * #isAnISATAPIPv6Address(String)} for boolean checks.
   */
  public static final Pattern ipv6ISATAPPattern;

  /**
   * IPv4 octet using ASCII-only digits. Sonar rule {@code java:S6353} suggests using the shorthand
   * {@code \d}; we intentionally keep {@code [0-9]} to avoid matching non‑ASCII digits under
   * Unicode-aware regex modes. This preserves compatibility with ASCII-only parsing such as {@link
   * Integer#parseInt(String)} and keeps IPv4 literals strictly ASCII.
   */
  @SuppressWarnings("java:S6353")
  private static final String IPV4_BYTE_REGEX_ASCII = "(?>2[0-4][0-9]|25[0-5]|[01]?[0-9]?[0-9]?)";

  static {
    String ipv4AddressRegex =
        IPV4_BYTE_REGEX_ASCII
            + "\\.(?>"
            + IPV4_BYTE_REGEX_ASCII
            + "\\.)?(?>"
            + IPV4_BYTE_REGEX_ASCII
            + "\\.)?"
            + IPV4_BYTE_REGEX_ASCII;
    ipv4Pattern = Pattern.compile(ipv4AddressRegex);

    String wordRegex = "(?>[0-9a-f]{1,4})"; // single hex word; atomic to limit backtracking
    // Accept numeric or interface-name zone indices: 1–32 of [0-9A-Za-z._-]
    String percentScopeIDRegex = "(?>%[0-9A-Za-z._-]{1,32})?";
    /*
     * IPv6 recognition in compressed/expanded forms. The following alternatives cover the legal
     * positions of the double-colon run and remaining words (X = hex word):
     *
     *   ::(?>(?>X:){0,6}X)?
     *   X::(?>(?>X:){0,5}X)?
     *   X:X::(?>(?>X:){0,4}X)?
     *   X:X:X::(?>(?>X:){0,3}X)?
     *   (?>X:){4}:(?>(?>X:){0,2}X)?
     *   (?>X:){5}:(?>X:)?X?
     *   (?>X:){6}:X?
     *   (?>X:){7}(?>X|:)
     */
    @SuppressWarnings("RegExpSingleCharAlternation")
    String ipv6AddressRegex =
        "::(?>(?>X:){0,6}X)?|X::(?>(?>X:){0,5}X)?|X:X::(?>(?>X:){0,4}X)?|X:X:X::(?>(?>X:){0,3}X)?|(?>X:){4}:(?>(?>X:){0,2}X)?|(?>X:){5}:(?>X:)?X?|(?>X:){6}:X?|(?>X:){7}(?>X|:)";
    ipv6AddressRegex = ipv6AddressRegex.replace("X", wordRegex);
    // ISATAP forms per RFC 4214 (5EFE marker in the Interface Identifier)
    // case 0: :(?>(?>:X){1,3}:0{1,4}|:0{1,4}|):5EFE:X:X
    // case 1: X:(?>:0{1,4}|:(?>X:){1,2}0{1,4}|):5EFE:X:X
    // case 2: X:X:(?>:0{1,4}|:(?>X:)?0{1,4}|):5EFE:X:X
    // case 3 and 4: X:X:X:(?>X:0{1,4}|:0{1,4}|X:|):5EFE:X:X
    // case 5: (?>X:){4}0{1,4}:5EFE:(?>X:X|:X?|X::)
    String ipv6ISATAPAddressRegex =
        ":(?>(?>:X){1,3}:0{1,4}|:0{1,4}|):5EFE:X:X|X:(?>:0{1,4}|:(?>X:){1,2}0{1,4}|):5EFE:X:X|X:X:(?>:0{1,4}|:(?>X:)?0{1,4}|):5EFE:X:X|X:X:X:(?>X:0{1,4}|:0{1,4}|X:|):5EFE:X:X|(?>X:){4}0{1,4}:5EFE:(?>X:X|:X?|X::)";
    ipv6ISATAPAddressRegex = ipv6ISATAPAddressRegex.replace("X", wordRegex);
    ipv6Pattern = Pattern.compile(ipv6AddressRegex, Pattern.CASE_INSENSITIVE);
    ipv6PatternWithPercentScopeID =
        Pattern.compile(
            "(?>" + ipv6AddressRegex + ")" + percentScopeIDRegex, Pattern.CASE_INSENSITIVE);
    ipv6ISATAPPattern =
        Pattern.compile(
            "(?>" + ipv6ISATAPAddressRegex + ")" + percentScopeIDRegex, Pattern.CASE_INSENSITIVE);
  }

  /** Categories recognized by {@link #getAddressType(String)}. */
  public enum AddressType {
    OTHER,
    IPV4,
    IPV6
  }

  /**
   * Returns the type of the supplied address literal.
   *
   * <p>This overload treats IPv6 inputs with a numeric percent scope ID as valid (equivalent to
   * calling {@link #getAddressType(String, boolean)} with {@code allowIPv6PercentScopeID = true}).
   * Hostnames and other non-literal inputs return {@link AddressType#OTHER}.
   *
   * @param address non-{@code null} address string to classify; the entire string must match a
   *     supported literal form to be considered IPv4 or IPv6
   * @return {@link AddressType#OTHER} for hostnames or non-literals; {@link AddressType#IPV4} or
   *     {@link AddressType#IPV6} for recognized numeric address literals
   * @throws NullPointerException if {@code address} is {@code null}
   */
  public static AddressType getAddressType(String address) {
    return AddressIdentifier.getAddressType(address, true);
  }

  /**
   * Returns the type of the supplied address literal.
   *
   * <p>When {@code allowIPv6PercentScopeID} is {@code true}, an IPv6 address may end with a numeric
   * zone index (for example, {@code %2}); interface-name scope IDs are not matched.
   *
   * @param address non-{@code null} address string to classify; the entire string must match a
   *     supported literal form to be considered IPv4 or IPv6
   * @param allowIPv6PercentScopeID whether to accept an optional numeric percent scope ID on IPv6
   *     inputs
   * @return {@link AddressType#OTHER} for hostnames or non-literals; {@link AddressType#IPV4} or
   *     {@link AddressType#IPV6} for recognized numeric address literals
   * @throws NullPointerException if {@code address} is {@code null}
   */
  public static AddressType getAddressType(String address, boolean allowIPv6PercentScopeID) {
    if (ipv4Pattern.matcher(address).matches()) {
      return AddressType.IPV4;
    } else if ((allowIPv6PercentScopeID ? ipv6PatternWithPercentScopeID : ipv6Pattern)
        .matcher(address)
        .matches()) {
      return AddressType.IPV6;
    }
    return AddressType.OTHER;
  }

  /**
   * Returns {@code true} if the input is an IPv6 ISATAP address as defined by RFC&nbsp;4214. The
   * check accepts optional numeric percent scope IDs.
   *
   * @param address non-{@code null} address string to test
   * @return {@code true} if {@code address} matches an ISATAP form; {@code false} otherwise
   * @throws NullPointerException if {@code address} is {@code null}
   * @see <a href="http://www.ietf.org/rfc/rfc4214.txt">RFC 4214</a>
   */
  public static boolean isAnISATAPIPv6Address(String address) {
    return ipv6ISATAPPattern.matcher(address).matches();
  }
}
