package network.crypta.io;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.StringTokenizer;

/**
 * Matches IPv4 addresses against a rule consisting of an address and optional mask.
 *
 * <p>The matcher behaves similarly to a regular-expression matcher in spirit: construct an instance
 * with a rule, then call {@link #matches(InetAddress)} to test addresses. Supported rule forms are:
 *
 * <ul>
 *   <li>Single address: {@code 192.168.1.2}
 *   <li>Dotted decimal mask: {@code 192.168.1.2/255.255.255.0}
 *   <li>CIDR mask length (bits): {@code 192.168.1.2/24}
 * </ul>
 *
 * <p>Non-contiguous masks are supported when provided in dotted form. Matching is purely bitwise
 * and performs no DNS lookups. Instances are effectively immutable after construction and are
 * thread-safe for concurrent use. Match evaluation runs in constant time.
 *
 * @author David Roden &lt;droden@gmail.com&gt;
 * @version $Id$
 */
public final class Inet4AddressMatcher implements AddressMatcher {
  /**
   * Packed IPv4 address of the rule in big-endian order (octet 1 in bits 24–31, octet 4 in 0–7).
   */
  private final int address;

  /**
   * Packed IPv4 network mask. A full mask ({@code 0xffffffff}) denotes an exact address match; a
   * zero mask ({@code 0x00000000}) matches any IPv4 address.
   */
  private int networkMask;

  /**
   * Creates a matcher from an IPv4 rule.
   *
   * <p>The rule may be a single address, an address with CIDR mask length (e.g., {@code /24}), or
   * an address with a dotted mask (e.g., {@code /255.255.255.0}).
   *
   * @param cidrHostname address rule to apply; must be in dotted-decimal IPv4 form. The part after
   *     {@code '/'} is either a decimal mask length (0–32) or a dotted mask.
   * @throws IllegalArgumentException if a mask length is provided and is outside {@code 0..32}.
   * @throws NumberFormatException if any decimal component cannot be parsed.
   * @throws java.util.NoSuchElementException if the address or dotted mask does not contain four
   *     dot-separated components.
   */
  public Inet4AddressMatcher(String cidrHostname) throws IllegalArgumentException {
    int slashPosition = cidrHostname.indexOf('/');
    if (slashPosition == -1) {
      address = convertToBytes(cidrHostname);
      networkMask = 0xffffffff;
    } else {
      address = convertToBytes(cidrHostname.substring(0, slashPosition));
      String maskPart = cidrHostname.substring(slashPosition + 1);
      if (maskPart.indexOf('.') == -1) {
        int bits = Integer.parseInt(maskPart);
        if (bits > 32 || bits < 0)
          throw new IllegalArgumentException(
              "Mask bits out of range: " + bits + " (" + maskPart + ")");
        // Build a contiguous mask from the length. Special-case zero to avoid relying on Java's
        // shift semantics on 32-bit ints (shifts are masked to 0..31), which would otherwise keep
        // 0xffffffff unchanged when shifting by 32.
        networkMask = 0xffffffff << (32 - bits);
        if (Integer.parseInt(maskPart) == 0) {
          networkMask = 0;
        }
      } else {
        networkMask = convertToBytes(maskPart);
      }
    }
  }

  /**
   * Converts {@code a.b.c.d} to a packed 32-bit integer.
   *
   * <p>Octet positions are: 1 → bits 24–31, 2 → 16–23, 3 → 8–15, 4 → 0–7.
   *
   * @param address dotted-decimal IPv4 literal.
   * @return packed IPv4 address in big-endian order.
   * @throws NumberFormatException if any component cannot be parsed by {@link Integer#parseInt}.
   * @throws java.util.NoSuchElementException if the input does not contain exactly four components.
   */
  public static int convertToBytes(String address) {
    StringTokenizer addressTokens = new StringTokenizer(address, ".");
    return Integer.parseInt(addressTokens.nextToken()) << 24
        | Integer.parseInt(addressTokens.nextToken()) << 16
        | Integer.parseInt(addressTokens.nextToken()) << 8
        | Integer.parseInt(addressTokens.nextToken());
  }

  /**
   * Tests whether the provided address satisfies this rule.
   *
   * <p>Only IPv4 addresses are considered; non-IPv4 inputs (e.g., IPv6) return {@code false}. The
   * check is a bitwise comparison under the configured mask and performs no I/O.
   *
   * @param inetAddress address to test; must not be {@code null}.
   * @return {@code true} if the address matches; {@code false} otherwise.
   */
  @Override
  public boolean matches(InetAddress inetAddress) {
    if (!(inetAddress instanceof Inet4Address)) return false;
    int matchAddress = convertToBytes(inetAddress.getHostAddress());
    return (matchAddress & networkMask) == (address & networkMask);
  }

  /**
   * Convenience method that constructs a matcher and tests the given address.
   *
   * @param cidrHostname rule in the forms described in the constructor.
   * @param address address to test.
   * @return {@code true} if the address matches; {@code false} otherwise.
   * @throws IllegalArgumentException if the rule contains an out-of-range mask length.
   * @throws NumberFormatException if any decimal component cannot be parsed.
   * @throws java.util.NoSuchElementException if the address or dotted mask is malformed.
   * @see #Inet4AddressMatcher(String)
   * @see #matches(InetAddress)
   */
  public static boolean matches(String cidrHostname, InetAddress address) {
    return new Inet4AddressMatcher(cidrHostname).matches(address);
  }

  @Override
  public String getHumanRepresentation() {
    if (networkMask == -1) return convertToString(address);
    else return convertToString(address) + '/' + convertToString(networkMask);
  }

  // Render an int-packed address/mask back to dotted decimal without allocations per octet.
  private String convertToString(int addr) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 4; i++) {
      int x = addr >>> 24;
      addr = addr << 8;
      if (i != 0) sb.append('.');
      sb.append(x);
    }
    return sb.toString();
  }
}
