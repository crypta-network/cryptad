package network.crypta.io;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for {@link AllowedHosts}. */
@ExtendWith(MockitoExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
@SuppressWarnings("java:S100") // test naming: method_whenCondition_expectOutcome
class AllowedHostsTest {

  @Test
  @DisplayName("setAllowedHosts(null/empty) falls back to defaults and allows loopback")
  void setAllowedHosts_whenNullOrEmpty_useDefaults() throws Exception {
    // Arrange
    AllowedHosts ahNull = new AllowedHosts(null);
    AllowedHosts ahEmpty = new AllowedHosts("");

    // Act
    String defaultsNull = ahNull.getAllowedHosts();
    String defaultsEmpty = ahEmpty.getAllowedHosts();

    // Assert
    assertEquals(
        NetworkInterface.DEFAULT_BIND_TO, defaultsNull, "Expected default allowed hosts (null)");
    assertEquals(
        NetworkInterface.DEFAULT_BIND_TO, defaultsEmpty, "Expected default allowed hosts (empty)");

    InetAddress loop4 = addr("127.0.0.1");
    InetAddress loop6 = addr("::1");
    assertTrue(ahNull.allowed(loop4));
    assertTrue(ahNull.allowed(loop6));
    assertTrue(ahEmpty.allowed(loop4));
    assertTrue(ahEmpty.allowed(loop6));
  }

  @Test
  @DisplayName("Wildcard '*' allows everything and is reflected by getAllowedHosts()")
  void getAllowedHosts_whenContainsWildcard_returnsStar() throws Exception {
    // Arrange
    AllowedHosts ahOnlyStar = new AllowedHosts("*");
    AllowedHosts ahMixed = new AllowedHosts("127.0.0.1,*,192.168.0.0/16");

    // Act & Assert
    assertEquals("*", ahOnlyStar.getAllowedHosts());
    assertEquals("*", ahMixed.getAllowedHosts());

    InetAddress any4 = addr("203.0.113.9"); // TEST-NET-3
    InetAddress any6 = addr("2001:db8::dead:beef");
    assertTrue(ahOnlyStar.allowed(any4));
    assertTrue(ahOnlyStar.allowed(any6));
    assertTrue(ahMixed.allowed(any4));
    assertTrue(ahMixed.allowed(any6));
  }

  @ParameterizedTest
  @MethodSource("ipv4Cases")
  @DisplayName("IPv4 CIDR and dotted-mask rules match as expected")
  void allowed_whenIPv4Rules_expectMatch(String rule, String candidate, boolean expected)
      throws Exception {
    // Arrange
    AllowedHosts ah = new AllowedHosts(rule);
    InetAddress addr = addr(candidate);

    // Act / Assert
    assertEquals(expected, ah.allowed(addr));
  }

  private Stream<Arguments> ipv4Cases() {
    return Stream.of(
        // Single host exact match
        Arguments.of("192.168.1.2", "192.168.1.2", true),
        Arguments.of("192.168.1.2", "192.168.1.3", false),
        // CIDR length
        Arguments.of("192.168.1.0/24", "192.168.1.123", true),
        Arguments.of("192.168.1.0/24", "192.168.2.1", false),
        // Dotted mask
        Arguments.of("10.0.0.0/255.0.0.0", "10.200.3.4", true),
        Arguments.of("10.0.0.0/255.0.0.0", "11.0.0.1", false));
  }

  @ParameterizedTest
  @MethodSource("ipv6Cases")
  @DisplayName("IPv6 prefix and explicit-mask rules match as expected")
  void allowed_whenIPv6Rules_expectMatch(String rule, String candidate, boolean expected)
      throws Exception {
    // Arrange
    AllowedHosts ah = new AllowedHosts(rule);
    InetAddress addr = addr(candidate);

    // Act
    boolean actual = ah.allowed(addr);

    // Assert with explicit branch to avoid duplicating the IPv4 test's structure
    if (expected) {
      assertTrue(
          actual,
          () -> "Expected IPv6 match for rule '" + rule + "' and address '" + candidate + "'");
    } else {
      assertFalse(
          actual,
          () -> "Expected IPv6 non-match for rule '" + rule + "' and address '" + candidate + "'");
    }
  }

  private Stream<Arguments> ipv6Cases() {
    return Stream.of(
        // Exact address
        Arguments.of("2001:db8::1", "2001:db8::1", true),
        Arguments.of("2001:db8::1", "2001:db8::2", false),
        // Prefix length
        Arguments.of("2001:db8::/32", "2001:db8::abcd", true),
        Arguments.of("2001:db8::/32", "2001:db9::1", false),
        // Explicit mask equals /64
        Arguments.of(
            "2001:db8::/ffff:ffff:ffff:ffff::",
            "2001:db8:0:1::1",
            false // first 64 bits differ (0 vs 1 in the 4th hextet)
            ),
        Arguments.of("2001:db8::/ffff:ffff:ffff:ffff::", "2001:db8::1234", true));
  }

  @Test
  @DisplayName("getAllowedHosts renders canonical forms for IPv4/IPv6 and masks")
  void getAllowedHosts_whenRulesProvided_expectCanonicalForms() {
    // Arrange
    AllowedHosts ah = new AllowedHosts("192.168.1.0/24,::1,10.0.0.1/8");

    // Act
    String rendered = ah.getAllowedHosts();

    // Assert
    assertEquals(
        "192.168.1.0/255.255.255.0,0:0:0:0:0:0:0:1,10.0.0.1/255.0.0.0",
        rendered,
        "Expected uncompressed IPv6 and dotted IPv4 masks");
  }

  @Test
  @DisplayName("Invalid hostname tokens are ignored; list becomes empty and denies all")
  void setAllowedHosts_whenInvalidHost_ignoredAndDeniesAll() throws UnknownHostException {
    // Arrange
    AllowedHosts ah = new AllowedHosts("localhost"); // not a numeric literal → ignored

    // Act
    String rendered = ah.getAllowedHosts();
    boolean allowed4 = ah.allowed(addr("127.0.0.1"));
    boolean allowed6 = ah.allowed(addr("::1"));

    // Assert
    assertEquals("", rendered);
    assertFalse(allowed4);
    assertFalse(allowed6);
  }

  @Test
  @DisplayName("Invalid IPv4/IPv6 masks or percent scopes cause constructor to throw")
  void setAllowedHosts_whenInvalidMasksOrZone_throws() {
    // IPv4 mask length out of range
    assertThrows(IllegalArgumentException.class, () -> new AllowedHosts("192.168.0.1/33"));
    // IPv6 prefix length out of range
    assertThrows(IllegalArgumentException.class, () -> new AllowedHosts("2001:db8::/129"));
    // IPv6 with numeric zone ID is classified as IPv6 by AddressIdentifier but not accepted by
    // matcher
    assertThrows(IllegalArgumentException.class, () -> new AllowedHosts("fe80::1%2"));
  }

  private static InetAddress addr(String host) throws UnknownHostException {
    return InetAddress.getAllByName(host)[0];
  }
}
