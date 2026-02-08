package network.crypta.support.transport.ip;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for {@link IPUtil} covering IPv4/IPv6 ranges and edge conditions.
 *
 * <p>Naming: method_whenCondition_expectOutcome (AAA style inside each test).
 */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test naming: method_whenCondition_expectOutcome
class IPUtilTest {

  // ---------- Helpers ----------

  private static InetAddress ip(String literal) {
    try {
      return InetAddress.getByName(literal);
    } catch (UnknownHostException e) {
      throw new AssertionError("Failed to parse IP literal: " + literal, e);
    }
  }

  // no dedicated ipv4-bytes helper to avoid Sonar flagging constant parameters

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
      // Arrange + Act + Assert
      assertThrows(NullPointerException.class, () -> IPUtil.isSiteLocalAddress(null));
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
        Arguments.of(ip("fec0::1")),
        // Upper bound of fec0::/10 → feff::/10
        Arguments.of(ip("feff::1")));
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
      InetAddress zeroLeading = ip("0.1.2.3");

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
    @SuppressWarnings("DataFlowIssue")
    void isValidAddress_whenNull_expectNullPointerException() {
      // Arrange + Act + Assert
      assertThrows(NullPointerException.class, () -> IPUtil.isValidAddress(null, true));
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
    byte[] fdUla = new byte[] {(byte) 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    // Act
    InetAddress addr = ipv6(fdUla);

    // Assert
    assertInstanceOf(Inet6Address.class, addr);
    assertEquals(16, addr.getAddress().length);
  }

  @Test
  void isSiteLocalAddress_whenIPv6MappedPrivateIPv4_expectTrueByJvmNormalization() {
    // Arrange: IPv4-mapped IPv6 for a private IPv4 address. JDK normalizes to Inet4Address.
    byte[] mappedBytes =
        new byte[] {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff, (byte) 192, (byte) 168, 1, 50
        };
    InetAddress mapped = ipv6(mappedBytes);
    assertFalse(mapped instanceof Inet6Address);
    assertEquals(4, mapped.getAddress().length);

    // Act
    boolean result = IPUtil.isSiteLocalAddress(mapped);

    // Assert: treated as IPv4 RFC1918 site-local
    assertTrue(result);
  }

  @Test
  void isValidAddress_whenIPv6MappedPrivateIPv4_expectMirrorsIncludeLocal() {
    // Arrange: explicit 16-byte IPv6-mapped address; JDK normalizes to IPv4
    byte[] mappedBytes =
        new byte[] {
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff, (byte) 192, (byte) 168, 1, 50
        };
    InetAddress mapped = ipv6(mappedBytes);
    assertFalse(mapped instanceof Inet6Address);
    assertEquals(4, mapped.getAddress().length);

    // Act
    boolean include = IPUtil.isValidAddress(mapped, true);
    boolean exclude = IPUtil.isValidAddress(mapped, false);

    // Assert: behaves like IPv4 site-local (mirrors includeLocal flag)
    assertTrue(include);
    assertFalse(exclude);
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

  @Test
  void constructor_whenReflected_expectInstanceCreated() throws Exception {
    // Arrange
    Constructor<IPUtil> ctor = IPUtil.class.getDeclaredConstructor();
    ctor.setAccessible(true);

    // Act
    IPUtil instance = ctor.newInstance();

    // Assert
    assertInstanceOf(IPUtil.class, instance);
  }
}
