package network.crypta.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests for {@link Inet6AddressMatcher} covering parsing, matching, and representation.
 *
 * <p>Uses AAA style and parameterized inputs to exercise edge cases deterministically.
 */
@SuppressWarnings("java:S100") // Allow method_whenCondition_expectOutcome names
class Inet6AddressMatcherTest {

  @Test
  void getAddressType_whenCalled_returnsIPv6() {
    // Arrange
    Inet6AddressMatcher matcher = new Inet6AddressMatcher("::/0");

    // Act
    AddressIdentifier.AddressType type = matcher.getAddressType();

    // Assert
    assertEquals(AddressIdentifier.AddressType.IPV6, type);
  }

  @Test
  void matches_whenZeroPrefix_acceptsAnyIPv6() throws Exception {
    // Arrange
    Inet6AddressMatcher matcher = new Inet6AddressMatcher("::/0");

    // Act & Assert
    assertTrue(matcher.matches(addr("fe80::203:dff:fe22:420f")));
    assertTrue(matcher.matches(addr("::1")));
  }

  @ParameterizedTest
  @MethodSource("validAddressesForPrefix64")
  @DisplayName("matches: /64 should accept addresses sharing first 64 bits")
  void matches_whenPrefix64_sameFirst64Bits_matches(String candidate) throws Exception {
    // Arrange
    Inet6AddressMatcher matcher = new Inet6AddressMatcher("fe80:0:0:0:203:dff:fe22:420f/64");

    // Act
    boolean result = matcher.matches(addr(candidate));

    // Assert
    assertTrue(result);
  }

  static Stream<String> validAddressesForPrefix64() {
    return Stream.of(
        "fe80:0:0:0:203:dff:fe22:420f",
        "fe80:0:0:0:0203:0dff:fe22:420f",
        // different 5th hextet is still allowed for /64
        "fe80:0:0:0:0204:0dff:fe22:420f",
        // any tail is fine when first four hextets match
        "fe80:0:0:0:0:0:0:1");
  }

  @ParameterizedTest
  @MethodSource("nonMatchingForPrefix64")
  @DisplayName("matches: /64 should reject different first 64 bits")
  void matches_whenPrefix64_differentFirst64Bits_rejects(String candidate) throws Exception {
    // Arrange
    Inet6AddressMatcher matcher = new Inet6AddressMatcher("fe80:0:0:0:203:dff:fe22:420f/64");

    // Act
    boolean result = matcher.matches(addr(candidate));

    // Assert
    assertFalse(result);
  }

  static Stream<String> nonMatchingForPrefix64() {
    return Stream.of(
        // first hextet differs
        "fe81:0:0:0:0203:0dff:fe22:420f",
        // entirely different network
        "0:0:0:0:0:0:0:1");
  }

  @Test
  void matches_whenPrefix128_requiresExactMatch() throws Exception {
    // Arrange
    Inet6AddressMatcher matcher = new Inet6AddressMatcher("fe80:0:0:0:203:dff:fe22:420f/128");

    // Act & Assert
    assertTrue(matcher.matches(addr("fe80:0:0:0:203:dff:fe22:420f")));
    assertFalse(matcher.matches(addr("fe80:0:0:0:0204:0dff:fe22:420f")));
    assertFalse(matcher.matches(addr("fe81:0:0:0:0203:0dff:fe22:420f")));
    assertFalse(matcher.matches(addr("0:0:0:0:0:0:0:1")));
    assertFalse(matcher.matches(addr("fe80:0:0:0:0:0:0:1")));
  }

  @Test
  void matches_whenStringNetmask_equivalentToPrefix64() throws Exception {
    // Arrange
    Inet6AddressMatcher matcher =
        new Inet6AddressMatcher("fe80:0:0:0:203:dff:fe22:420f/ffff:ffff:ffff:ffff:0:0:0:0");

    // Act & Assert
    assertTrue(matcher.matches(addr("fe80:0:0:0:0203:0dff:fe22:420f")));
    assertTrue(matcher.matches(addr("fe80:0:0:0:0204:0dff:fe22:420f")));
    assertFalse(matcher.matches(addr("fe81:0:0:0:0203:0dff:fe22:420f")));
  }

  @Test
  void matches_whenAddressIsIPv4_returnsFalse() throws Exception {
    // Arrange
    Inet6AddressMatcher matcher = new Inet6AddressMatcher("::/0");

    // Act
    boolean result = matcher.matches(addr("127.0.0.1"));

    // Assert
    assertFalse(result, "IPv4 addresses must not match an IPv6 matcher");
  }

  @Test
  void staticMatches_whenPatternAndAddressMatch_returnsTrue() throws Exception {
    // Arrange
    InetAddress loopback6 = addr("::1");
    InetAddress linkLocal = addr("fe80::");

    // Act & Assert
    assertTrue(Inet6AddressMatcher.matches("::1", loopback6));
    assertTrue(Inet6AddressMatcher.matches("fe80::", linkLocal));
  }

  @ParameterizedTest
  @MethodSource("invalidPatterns")
  void constructor_whenInvalidPattern_throws(String pattern) {
    // Arrange + Act + Assert
    assertThrows(IllegalArgumentException.class, () -> new Inet6AddressMatcher(pattern));
  }

  static Stream<String> invalidPatterns() {
    return Stream.of(
        // not IPv6
        "192.168.1.1",
        // duplicate '::'
        "1::2::3",
        "::1::2",
        // too many hextets
        "::1:2:3:4:5:6:7:8",
        // single leading or trailing colon
        ":1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:",
        // out of range token
        "123456::789abcde",
        // triple colon
        ":::1",
        // percent scope id is not supported here
        "fe80::1%1",
        // invalid hex in string netmask
        "fe80::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:gggg");
  }

  @ParameterizedTest
  @MethodSource("invalidBitMasks")
  void constructor_whenBitMaskOutOfRange_throws(String pattern) {
    // Arrange + Act + Assert
    assertThrows(IllegalArgumentException.class, () -> new Inet6AddressMatcher(pattern));
  }

  static Stream<String> invalidBitMasks() {
    return Stream.of("::/-1", "::/129");
  }

  @Test
  void constructor_whenValidFull8Hextets_parsesSuccessfully() throws Exception {
    // Arrange
    String addr = "1:2:3:4:5:6:7:8";
    Inet6AddressMatcher matcher = new Inet6AddressMatcher(addr);

    // Act & Assert
    assertTrue(matcher.matches(addr(addr)));
  }

  @ParameterizedTest
  @MethodSource("humanRepresentationCases")
  void getHumanRepresentation_whenValidPatterns_expectCanonicalForm(
      String pattern, String expected) {
    // Arrange
    Inet6AddressMatcher matcher = new Inet6AddressMatcher(pattern);

    // Act
    String text = matcher.getHumanRepresentation();

    // Assert
    assertEquals(expected, text);
  }

  static Stream<Arguments> humanRepresentationCases() {
    return Stream.of(
        // /128 collapses to address only
        Arguments.of("fe80:0:0:0:203:dff:fe22:420f/128", "fe80:0:0:0:203:dff:fe22:420f"),
        // /0 shows address + netmask string
        Arguments.of("::/0", "0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0"),
        // Uppercase input canonicalizes to lowercase expanded
        Arguments.of("FE80:0:0:0:0203:0DFF:FE22:420F", "fe80:0:0:0:203:dff:fe22:420f"));
  }

  private static InetAddress addr(String literal) throws UnknownHostException {
    return InetAddress.getAllByName(literal)[0];
  }
}
