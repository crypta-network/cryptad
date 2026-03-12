package network.crypta.support.io;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link InetAddressComparator}.
 *
 * <p>Style: AAA (Arrange-Act-Assert). Deterministic and side effect free.
 */
class InetAddressComparatorTest {

  private static InetAddress ipv4(int a, int b, int c, int d) throws UnknownHostException {
    return InetAddress.getByAddress(new byte[] {(byte) a, (byte) b, (byte) c, (byte) d});
  }

  private static InetAddress ipv6(byte[] sixteen) throws UnknownHostException {
    assertEquals(16, sixteen.length, "IPv6 address must be 16 bytes");
    return InetAddress.getByAddress(sixteen);
  }

  @Test
  @DisplayName("compare_sameReference_expectZero")
  @SuppressWarnings("EqualsWithItself")
  void compare_sameReference_expectZero() throws Exception {
    // Arrange
    InetAddress addr = ipv4(127, 0, 0, 1);

    // Act
    int result = InetAddressComparator.COMPARATOR.compare(addr, addr);

    // Assert
    assertEquals(0, result);
  }

  static Stream<Arguments> ipv4OrderingCases() throws Exception {
    return Stream.of(
        Arguments.of(ipv4(0, 0, 0, 1), ipv4(0, 0, 0, 2), -1),
        Arguments.of(ipv4(0, 0, 0, 2), ipv4(0, 0, 0, 1), 1));
  }

  @ParameterizedTest(name = "{index}: {0} vs {1} => {2}")
  @MethodSource("ipv4OrderingCases")
  @DisplayName("compare_ipv4Order_whenDifferentHash_expectOutcome")
  void compare_ipv4Order_whenDifferentHash_expectOutcome(
      InetAddress left, InetAddress right, int expectedSign) {
    // Arrange (addresses already prepared)

    // Act
    int result = Integer.signum(InetAddressComparator.COMPARATOR.compare(left, right));

    // Assert: sign matches expectation
    assertEquals(expectedSign, result);
  }

  @Test
  @DisplayName("compare_ipv4SameBytesDifferentInstances_whenHashEqual_expectZero")
  void compare_ipv4SameBytesDifferentInstances_whenHashEqual_expectZero() throws Exception {
    // Arrange: two distinct objects with identical IPv4 bytes
    InetAddress a1 = ipv4(10, 20, 30, 40);
    InetAddress a2 = ipv4(10, 20, 30, 40);
    assertNotSame(a1, a2);
    assertEquals(a1.hashCode(), a2.hashCode(), "Precondition: equal hash codes");

    // Act
    int result = InetAddressComparator.COMPARATOR.compare(a1, a2);

    // Assert
    assertEquals(0, result);
  }

  @Nested
  class Ipv6VsIpv4TieBreak {
    @Test
    @DisplayName("compare_ipv6VsIpv4_whenEqualHash_expectIpv6Preferred")
    void compare_ipv6VsIpv4_whenEqualHash_expectIpv6Preferred() throws Exception {
      // Arrange: choose addresses whose hash codes are both 0: :: and 0.0.0.0
      InetAddress v6 = ipv6(new byte[16]);
      InetAddress v4 = ipv4(0, 0, 0, 0);
      assertEquals(v6.hashCode(), v4.hashCode(), "Precondition: equal hash codes");

      // Act
      int result = InetAddressComparator.COMPARATOR.compare(v6, v4);

      // Assert: IPv6 is preferred (ordered before) when hash is equal
      assertTrue(result < 0, "IPv6 should sort before IPv4 when hash ties");
    }

    @Test
    @DisplayName("compare_ipv4VsIpv6_whenEqualHash_expectIpv4After")
    void compare_ipv4VsIpv6_whenEqualHash_expectIpv4After() throws Exception {
      // Arrange
      InetAddress v6 = ipv6(new byte[16]);
      InetAddress v4 = ipv4(0, 0, 0, 0);
      assertEquals(v6.hashCode(), v4.hashCode(), "Precondition: equal hash codes");

      // Act
      int result = InetAddressComparator.COMPARATOR.compare(v4, v6);

      // Assert: IPv4 ordered after IPv6 when hashes tie
      assertTrue(result > 0, "IPv4 should sort after IPv6 when hash ties");
    }
  }

  // No Mockito tests: InetAddress is sealed in JDK 21, and there is no
  // external I/O or time source to mock for this comparator.

  @Nested
  class NullHandling {
    @Test
    @DisplayName("compare_nullAndNonNullLeft_whenNull_expectNullPointerException")
    void compare_nullAndNonNullLeft_whenNull_expectNullPointerException() throws Exception {
      // Arrange
      InetAddress nonNull = ipv4(1, 1, 1, 1);

      // Act + Assert
      assertThrows(
          NullPointerException.class,
          () -> InetAddressComparator.COMPARATOR.compare(null, nonNull));
    }

    @Test
    @DisplayName("compare_nonNullAndNullRight_whenNull_expectNullPointerException")
    void compare_nonNullAndNullRight_whenNull_expectNullPointerException() throws Exception {
      // Arrange
      InetAddress nonNull = ipv4(1, 1, 1, 1);

      // Act + Assert
      assertThrows(
          NullPointerException.class,
          () -> InetAddressComparator.COMPARATOR.compare(nonNull, null));
    }

    @Test
    @DisplayName("compare_bothNull_whenBothNull_expectZero")
    @SuppressWarnings("EqualsWithItself")
    void compare_bothNull_whenBothNull_expectZero() {
      // Arrange - nothing

      // Act
      int result = InetAddressComparator.COMPARATOR.compare(null, null);

      // Assert
      assertEquals(0, result);
    }
  }
}
