package network.crypta.support.transport.ip;

import static org.junit.jupiter.api.Assertions.*;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

/**
 * Tests for {@link IPUtil} covering IPv4/IPv6 ranges and edge conditions.
 *
 * <p>Naming: method_whenCondition_expectOutcome (AAA style inside each test).
 */
class IPUtilTest {

  // ---------- Helpers ----------

  private static InetAddress ip(String literal) {
    try {
      return InetAddress.getByName(literal);
    } catch (UnknownHostException e) {
      throw new AssertionError("Failed to parse IP literal: " + literal, e);
    }
  }

  private static InetAddress ipv4(byte a, byte b, byte c, byte d) {
    try {
      return InetAddress.getByAddress(new byte[] {a, b, c, d});
    } catch (UnknownHostException e) {
      throw new AssertionError(e);
    }
  }

  private static InetAddress ipv6(byte[] addr16) {
    assertEquals(16, addr16.length, "IPv6 address must be 16 bytes");
    try {
      return InetAddress.getByAddress(addr16);
    } catch (UnknownHostException e) {
      throw new AssertionError(e);
    }
  }

  // ---------- isSiteLocalAddress ----------

  @Nested
  @DisplayName("isSiteLocalAddress")
  class IsSiteLocalAddress {

    @ParameterizedTest(name = "{index} → {0} should be site-local")
    @MethodSource("network.crypta.support.transport.ip.IPUtilTest#siteLocalAddresses")
    void isSiteLocalAddress_whenSiteLocal_expectTrue(InetAddress addr) {
      // Arrange: address provided by params

      // Act
      boolean result = IPUtil.isSiteLocalAddress(addr);

      // Assert
      assertTrue(result, () -> "Expected site-local for: " + addr);
    }

    @ParameterizedTest(name = "{index} → {0} should NOT be site-local")
    @MethodSource("network.crypta.support.transport.ip.IPUtilTest#nonSiteLocalAddresses")
    void isSiteLocalAddress_whenNotSiteLocal_expectFalse(InetAddress addr) {
      // Arrange: address provided by params

      // Act
      boolean result = IPUtil.isSiteLocalAddress(addr);

      // Assert
      assertFalse(result, () -> "Expected NOT site-local for: " + addr);
    }

    @Test
    void isSiteLocalAddress_whenNull_expectNullPointerException() {
      // Arrange
      InetAddress addr = null;

      // Act + Assert
      assertThrows(NullPointerException.class, () -> IPUtil.isSiteLocalAddress(addr));
    }
  }

  static Stream<Arguments> siteLocalAddresses() {
    return Stream.of(
        // IPv4 RFC1918
        Arguments.of(ip("10.0.0.1")),
        Arguments.of(ip("172.16.0.1")),
        Arguments.of(ip("192.168.1.1")),
        // IPv6 ULA: fc00::/7 (both fc and fd)
        Arguments.of(ip("fc00::1")),
        Arguments.of(ip("fd12:3456::1")),
        // IPv6 deprecated site-local: fec0::/10
        Arguments.of(ip("fec0::1")));
  }

  static Stream<Arguments> nonSiteLocalAddresses() {
    return Stream.of(
        // IPv4 public
        Arguments.of(ip("8.8.8.8")),
        // IPv4 loopback (not site-local)
        Arguments.of(ip("127.0.0.1")),
        // IPv4 link-local (169.254/16 is link-local, not site-local)
        Arguments.of(ip("169.254.1.2")),
        // IPv6 link-local fe80::/10 (not site-local)
        Arguments.of(ip("fe80::1")),
        // IPv6 global unicast example
        Arguments.of(ip("2001:db8::1")));
  }

  // ---------- isValidAddress ----------

  @Nested
  @DisplayName("isValidAddress")
  class IsValidAddress {

    @ParameterizedTest(name = "{index} → {0} local={1} → expect {2}")
    @MethodSource("network.crypta.support.transport.ip.IPUtilTest#validityMatrix")
    void isValidAddress_whenVariousKinds_expectDefinedValidity(
        InetAddress addr, boolean includeLocal, boolean expected) {
      // Arrange handled by parameters

      // Act
      boolean result = IPUtil.isValidAddress(addr, includeLocal);

      // Assert
      assertEquals(
          expected, result, () -> String.format("addr=%s includeLocal=%s", addr, includeLocal));
    }

    @Test
    void isValidAddress_whenIPv4FirstOctetZero_expectFalse() {
      // Arrange
      InetAddress zeroLeading = ipv4((byte) 0, (byte) 1, (byte) 2, (byte) 3);

      // Act
      boolean resultWhenInclude = IPUtil.isValidAddress(zeroLeading, true);
      boolean resultWhenExclude = IPUtil.isValidAddress(zeroLeading, false);

      // Assert
      assertFalse(resultWhenInclude);
      assertFalse(resultWhenExclude);
    }

    @Test
    void isValidAddress_whenIPv4AnyLocal_0_0_0_0_expectFalse() {
      // Arrange
      InetAddress any = ip("0.0.0.0");

      // Act
      boolean result = IPUtil.isValidAddress(any, true);

      // Assert
      assertFalse(result);
    }

    @Test
    void isValidAddress_whenIPv6Unspecified_expectFalse() {
      // Arrange
      InetAddress unspecified = ip("::");
      assertTrue(unspecified.isAnyLocalAddress());

      // Act
      boolean result = IPUtil.isValidAddress(unspecified, true);

      // Assert
      assertFalse(result);
    }

    @Test
    void isValidAddress_whenNull_expectNullPointerException() {
      // Arrange
      InetAddress addr = null;

      // Act + Assert
      assertThrows(NullPointerException.class, () -> IPUtil.isValidAddress(addr, true));
    }
  }

  static Stream<Arguments> validityMatrix() {
    return Stream.of(
        // Public IPv4 → always valid
        Arguments.of(ip("8.8.8.8"), true, true),
        Arguments.of(ip("8.8.8.8"), false, true),

        // Multicast IPv4 → invalid
        Arguments.of(ip("224.0.0.1"), true, false),
        Arguments.of(ip("224.0.0.1"), false, false),

        // Loopback IPv4 → mirrors includeLocal
        Arguments.of(ip("127.0.0.1"), true, true),
        Arguments.of(ip("127.0.0.1"), false, false),

        // Link-local IPv4 → mirrors includeLocal
        Arguments.of(ip("169.254.10.20"), true, true),
        Arguments.of(ip("169.254.10.20"), false, false),

        // Site-local IPv4 → mirrors includeLocal
        Arguments.of(ip("10.1.2.3"), true, true),
        Arguments.of(ip("10.1.2.3"), false, false),
        Arguments.of(ip("192.168.7.8"), true, true),
        Arguments.of(ip("192.168.7.8"), false, false),

        // IPv6 global → always valid
        Arguments.of(ip("2001:db8::1"), true, true),
        Arguments.of(ip("2001:db8::1"), false, true),

        // IPv6 multicast → invalid
        Arguments.of(ip("ff02::1"), true, false),
        Arguments.of(ip("ff02::1"), false, false),

        // IPv6 loopback → mirrors includeLocal
        Arguments.of(ip("::1"), true, true),
        Arguments.of(ip("::1"), false, false),

        // IPv6 link-local → mirrors includeLocal
        Arguments.of(ip("fe80::1234"), true, true),
        Arguments.of(ip("fe80::1234"), false, false),

        // IPv6 ULA/site-local → mirrors includeLocal
        Arguments.of(ip("fc00::1"), true, true),
        Arguments.of(ip("fc00::1"), false, false),
        Arguments.of(ip("fec0::1"), true, true),
        Arguments.of(ip("fec0::1"), false, false));
  }

  // ---------- Sanity checks on address construction ----------

  @Test
  void helper_ipv6Bytes_createsInet6Address() {
    // Arrange
    byte[] fd_ula = new byte[] {(byte) 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    // Act
    InetAddress addr = ipv6(fd_ula);

    // Assert
    assertTrue(addr instanceof Inet6Address);
    assertEquals(16, addr.getAddress().length);
  }

  @Test
  void isValidAddress_whenAnyLocalAddressMocked_expectFalse() {
    // Arrange
    InetAddress mocked = Mockito.mock(InetAddress.class);
    Mockito.when(mocked.isAnyLocalAddress()).thenReturn(true);

    // Act
    boolean result = IPUtil.isValidAddress(mocked, true);

    // Assert
    assertFalse(result);
  }

  @Test
  void isValidAddress_whenIPv4Broadcast_expectTrue() {
    // Arrange
    InetAddress broadcast = ip("255.255.255.255");

    // Act
    boolean result = IPUtil.isValidAddress(broadcast, false);

    // Assert
    assertTrue(result);
  }
}
