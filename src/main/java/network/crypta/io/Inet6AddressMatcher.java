package network.crypta.io;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Arrays;
import network.crypta.io.AddressIdentifier.AddressType;

/**
 * Matches IPv6 addresses against a pattern with an optional netmask.
 *
 * <p>The {@code pattern} can be one of the following forms:
 *
 * <ul>
 *   <li>A literal IPv6 address, for example {@code 2001:db8::1}.
 *   <li>An address with a prefix length, for example {@code 2001:db8::/64}.
 *   <li>An address with an explicit mask address, for example {@code
 *       2001:db8::/ffff:ffff:ffff:ffff::}.
 * </ul>
 *
 * <p>Zero-compression ({@code ::}) is accepted during parsing. Rendering via {@link
 * #getHumanRepresentation()} does not perform zero-compression; groups are printed in uncompressed
 * hexadecimal. Instances are immutable after construction and are safe for concurrent use.
 *
 * @author David Roden &lt;droden@gmail.com&gt;
 * @version $Id$
 */
public class Inet6AddressMatcher implements AddressMatcher {
  /**
   * Returns the address family supported by this matcher.
   *
   * @return {@link AddressType#IPV6}
   */
  public AddressType getAddressType() {
    return AddressType.IPV6;
  }

  private static final byte[] FULL_MASK = new byte[16];

  static {
    Arrays.fill(FULL_MASK, (byte) 0xff);
  }

  private final byte[] address;
  private byte[] netmask;

  /**
   * Creates a matcher from an IPv6 pattern.
   *
   * <p>Accepted forms are a literal IPv6 address, an address with a prefix length (e.g., {@code
   * /64}), or an address with an explicit 128-bit mask address. A prefix length must be in the
   * range {@code 0..128}.
   *
   * @param pattern IPv6 pattern to match against.
   * @throws IllegalArgumentException if the pattern is syntactically invalid, not IPv6, or the
   *     prefix length is outside {@code 0..128}.
   */
  public Inet6AddressMatcher(String pattern) throws IllegalArgumentException {
    if (pattern.indexOf('/') != -1) {
      address = convertToBytes(pattern.substring(0, pattern.indexOf('/')));
      String netmaskString = pattern.substring(pattern.indexOf('/') + 1).trim();
      if (netmaskString.indexOf(':') != -1) {
        netmask = convertToBytes(netmaskString);
      } else {
        netmask = new byte[16];
        int bits = Integer.parseInt(netmaskString);
        if (bits > 128 || bits < 0)
          throw new IllegalArgumentException(
              "Mask bits out of range: " + bits + " (" + netmaskString + ")");
        for (int index = 0; index < 16; index++) {
          netmask[index] = (byte) (255 << (8 - Math.min(bits, 8)));
          bits = Math.max(bits - 8, 0);
        }
      }
      if (Arrays.equals(netmask, FULL_MASK)) netmask = FULL_MASK;
    } else {
      address = convertToBytes(pattern);
      netmask = FULL_MASK;
    }
    if (address.length != 16) {
      throw new IllegalArgumentException("address is not IPv6");
    }
  }

  /**
   * Parses an IPv6 string into a 16-byte array.
   *
   * <p>Supports zero-compression ({@code ::}). The method validates that no more than eight 16-bit
   * groups are provided and that {@code ::} expands to at least one group.
   *
   * @param addrString IPv6 address literal.
   * @return 16-byte address in network byte order.
   * @throws IllegalArgumentException if {@code addrString} is not a valid IPv6 literal.
   */
  private byte[] convertToBytes(String addrString) throws IllegalArgumentException {
    if ("::".equals(addrString)) {
      return new byte[16]; // All zeros: 0:0:0:0:0:0:0:0
    }
    // Tokenize without discarding trailing empty strings to distinguish
    // "1:2:3:4:5:6:7:" from "1:2:3:4:5:6:7::".
    String[] addressTokens = addrString.split(":", -1);
    int tokenPosition;
    byte[] addressBytes = new byte[16]; // Words before '::'
    byte[] addressBytesEnd = new byte[16]; // Words after '::'
    int count = 0;
    int endCount;

    // Handle addresses starting with ':' (i.e., forms beginning with '::').
    int[] leading = handleLeadingColon(addrString);
    tokenPosition = leading[0];
    endCount = leading[1];
    if (tokenPosition == -1) {
      throw new IllegalArgumentException(addrString + " is not an IPv6 address.");
    }

    while (tokenPosition < addressTokens.length) {
      String token = addressTokens[tokenPosition++];
      if (token.isEmpty()) {
        endCount =
            handleEmptyToken(addrString, addressTokens.length, tokenPosition, count, endCount);
      } else if (endCount == -1) {
        int word = parseHextet(token, addrString);
        count = appendBeforeDoubleColon(addressBytes, count, word, addrString);
      } else {
        int word = parseHextet(token, addrString);
        endCount = appendAfterDoubleColon(addressBytesEnd, count, endCount, word, addrString);
      }
    }

    if (endCount != -1) {
      copyEndPart(addressBytes, addressBytesEnd, count, endCount);
    }
    return addressBytes;
  }

  /**
   * Determines the initial token position and the state of the tail-counter for inputs that start
   * with a colon. Returns {@code {-1, -1}} for invalid single-leading-colon inputs.
   */
  private static int[] handleLeadingColon(String addrString) {
    int tokenPosition = 0;
    int endCount = -1;
    if (addrString.startsWith(":")) {
      if (addrString.startsWith("::")) {
        if ("::".equals(addrString)) {
          // All zeros: 0:0:0:0:0:0:0:0
          return new int[] {0, 0};
        }
        tokenPosition = 2; // Skip the two empty tokens created by leading '::'
        endCount = 0;
      } else {
        // Single leading ':' is invalid
        return new int[] {-1, -1};
      }
    }
    return new int[] {tokenPosition, endCount};
  }

  /** Parses one 16-bit hexadecimal hextet. */
  private static int parseHextet(String token, String original) {
    try {
      int addressWord = Integer.parseInt(token, 16);
      if (addressWord < 0 || addressWord > 0xffff) {
        throw new IllegalArgumentException(original + " is not an IPv6 address.");
      }
      return addressWord;
    } catch (NumberFormatException _) {
      throw new IllegalArgumentException(original + " is not an IPv6 address.");
    }
  }

  /**
   * Appends a word to the head (before {@code ::}); fails if more than eight groups are present.
   */
  private static int appendBeforeDoubleColon(
      byte[] addressBytes, int count, int word, String original) {
    if (count >= 8) {
      throw new IllegalArgumentException(original + " is not an IPv6 address.");
    }
    addressBytes[count * 2] = (byte) ((word >> 8) & 0xff);
    addressBytes[count * 2 + 1] = (byte) (word & 0xff);
    return count + 1;
  }

  /**
   * Appends a word to the tail (after {@code ::}). Ensures the implicit gap covers at least one
   * group by requiring {@code count + endCount <= 7}.
   */
  private static int appendAfterDoubleColon(
      byte[] addressBytesEnd, int count, int endCount, int word, String original) {
    if (count + endCount >= 7) {
      throw new IllegalArgumentException(original + " is not an IPv6 address.");
    }
    addressBytesEnd[endCount * 2] = (byte) ((word >> 8) & 0xff);
    addressBytesEnd[endCount * 2 + 1] = (byte) (word & 0xff);
    return endCount + 1;
  }

  /** Handles empty tokens arising from {@code ::} and validates trailing-colon edge cases. */
  private static int handleEmptyToken(
      String original, int tokensLength, int tokenPosition, int count, int endCount) {
    if (endCount == -1) {
      if (count >= 8 || tokenPosition == tokensLength) {
        // Reject "1:2:3:4:5:6:7:8::"; allow "1:2:3:4:5:6:7::".
        throw new IllegalArgumentException(original + " is not an IPv6 address.");
      }
      return 0; // Start counting words that follow '::'
    }
    if (endCount > 0 || tokenPosition != tokensLength) {
      throw new IllegalArgumentException(original + " is not an IPv6 address.");
    }
    return endCount;
  }

  /**
   * Fills the implicit gap created by {@code ::} with zeros and copies the collected tail words to
   * the end of the output array.
   */
  private static void copyEndPart(
      byte[] addressBytes, byte[] addressBytesEnd, int count, int endCount) {
    for (int index = count; index < 8 - endCount; index++) {
      addressBytes[index * 2] = 0;
      addressBytes[index * 2 + 1] = 0;
    }
    for (int index = 0; index < endCount; index++) {
      addressBytes[(8 - endCount + index) * 2] = addressBytesEnd[index * 2];
      addressBytes[(8 - endCount + index) * 2 + 1] = addressBytesEnd[index * 2 + 1];
    }
  }

  /**
   * Tests whether the supplied address matches this matcher's pattern under the configured netmask.
   *
   * <p>The address must be an instance of {@link Inet6Address}. The comparison applies the netmask
   * bitwise to both the candidate address and the stored pattern and checks for equality.
   *
   * @param address address to test; non-IPv6 values yield {@code false}.
   * @return {@code true} if the address matches, otherwise {@code false}.
   */
  @Override
  public boolean matches(InetAddress address) {
    if (!(address instanceof Inet6Address)) return false;
    byte[] addressBytes = address.getAddress();
    for (int index = 0; index < 16; index++) {
      if ((addressBytes[index] & netmask[index]) != (this.address[index] & netmask[index])) {
        return false;
      }
    }
    return true;
  }

  /**
   * Convenience helper that constructs a matcher from {@code pattern} and tests the given address.
   * Equivalent to {@code new Inet6AddressMatcher(pattern).matches(inetAddress)}.
   *
   * @param pattern IPv6 pattern to match.
   * @param inetAddress address to test.
   * @return {@code true} if the address matches, otherwise {@code false}.
   * @throws IllegalArgumentException if {@code pattern} is invalid.
   */
  public static boolean matches(String pattern, InetAddress inetAddress)
      throws IllegalArgumentException {
    return new Inet6AddressMatcher(pattern).matches(inetAddress);
  }

  /**
   * Returns a human-readable representation of this matcher.
   *
   * <p>When the mask equals the full 128-bit mask, only the address is returned. Otherwise, the
   * format is {@code <address>/<maskAddress>}. Groups are not zero-compressed.
   *
   * @return canonical representation of the pattern.
   */
  @Override
  public String getHumanRepresentation() {
    if (Arrays.equals(netmask, FULL_MASK)) return convertToString(address);
    else return convertToString(address) + '/' + convertToString(netmask);
  }

  // Converts a 16-byte IPv6 address to an uncompressed hexadecimal string with ':' separators.
  private String convertToString(byte[] addr) {
    StringBuilder sb = new StringBuilder(4 * 8 + 7);
    for (int i = 0; i < 8; i++) {
      if (i != 0) sb.append(':');
      int token = ((addr[i * 2] & 0xff) << 8) + (addr[i * 2 + 1] & 0xff);
      sb.append(Integer.toHexString(token));
    }
    return sb.toString();
  }
}
