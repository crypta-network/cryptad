package network.crypta.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Tests for {@link Inet4AddressMatcher}.
 *
 * <p>Covers exact matches, CIDR and dotted-mask matching, edge/boundary behavior, error paths, and
 * human representation formatting. Uses only numeric IP literals to avoid DNS/I/O.
 */
@SuppressWarnings("java:S100") // Test method names use given_when_then style
class Inet4AddressMatcherTest {

  // ---------- Matching: exact (no mask) ----------

  @ParameterizedTest(name = "no-mask: 192.168.1.2 vs {0} -> {1}")
  @CsvSource({"192.168.1.1,false", "192.168.1.2,true", "127.0.0.1,false", "0.0.0.0,false"})
  void matches_whenNoMask_expectExactMatchOnly(String candidate, boolean expected)
      throws Exception {
    Inet4AddressMatcher matcher = new Inet4AddressMatcher("192.168.1.2");
    assertEquals(expected, matcher.matches(addr(candidate)));
  }

  // ---------- Matching: CIDR bits (/8) ----------

  @ParameterizedTest(name = "/8: 192.168.1.2 vs {0} -> {1}")
  @CsvSource({
    // same first octet -> match
    "192.168.1.1,true",
    "192.168.1.2,true",
    "192.168.2.1,true",
    "192.16.81.1,true",
    "192.255.255.255,true",
    // different first octet -> no match
    "172.16.1.1,false",
    "127.0.0.1,false",
    "0.0.0.0,false",
    // boundary
    "192.0.0.0,true"
  })
  void matches_whenMaskBits8_expectSameFirstOctetMatches(String candidate, boolean expected)
      throws Exception {
    Inet4AddressMatcher matcher = new Inet4AddressMatcher("192.168.1.2/8");
    assertEquals(expected, matcher.matches(addr(candidate)));
  }

  // ---------- Matching: non-contiguous dotted mask ----------

  @ParameterizedTest(name = "dotted-mask 255.0.255.0: 192.168.1.1 vs {0} -> {1}")
  @CsvSource({
    "192.168.1.1,true",
    "192.16.1.1,true",
    "192.168.2.1,false",
    "192.16.2.1,false",
    "127.0.0.1,false"
  })
  void matches_whenNonContiguousMask_expectBitwiseBehavior(String candidate, boolean expected)
      throws Exception {
    Inet4AddressMatcher matcher = new Inet4AddressMatcher("192.168.1.1/255.0.255.0");
    assertEquals(expected, matcher.matches(addr(candidate)));
  }

  // ---------- Matching: localhost /8 ----------

  @ParameterizedTest(name = "localhost/8: {0} -> {1}")
  @CsvSource({
    "127.0.0.1,true",
    "127.23.42.64,true",
    "127.0.0.0,true",
    "127.255.255.255,true",
    "28.0.0.1,false"
  })
  void matches_whenLocalhost8_expect127RangeOnly(String candidate, boolean expected)
      throws Exception {
    Inet4AddressMatcher matcher = new Inet4AddressMatcher("127.0.0.1/8");
    assertEquals(expected, matcher.matches(addr(candidate)));
  }

  // ---------- Matching: zero mask (/0) ----------

  @ParameterizedTest(name = "zero-mask/0 matches IPv4: {0}")
  @CsvSource({"127.0.0.1", "192.168.1.1", "192.168.2.1", "172.16.42.23", "10.0.0.1", "224.0.0.1"})
  void matches_whenZeroMask_expectAllIPv4Match(String candidate) throws Exception {
    Inet4AddressMatcher matcher = new Inet4AddressMatcher("0.0.0.0/0");
    assertTrue(matcher.matches(addr(candidate)));
  }

  @Test
  void matches_whenIPv6AddressProvided_expectFalseEvenForZeroMask() throws Exception {
    Inet4AddressMatcher matcher = new Inet4AddressMatcher("0.0.0.0/0");
    InetAddress ipv6 = addr("::1");
    assertFalse(matcher.matches(ipv6));
  }

  // ---------- Static matches() convenience ----------

  @Test
  void staticMatches_whenUsed_expectSameAsInstance() throws Exception {
    InetAddress a = addr("192.168.1.1");
    assertTrue(Inet4AddressMatcher.matches("192.168.1.0/24", a));
    assertFalse(Inet4AddressMatcher.matches("10.0.0.0/8", a));
  }

  // ---------- getHumanRepresentation() formatting ----------

  @Test
  void getHumanRepresentation_whenExactMask_expectIpOnly() {
    Inet4AddressMatcher m1 = new Inet4AddressMatcher("192.168.1.2");
    assertEquals("192.168.1.2", m1.getHumanRepresentation());

    Inet4AddressMatcher m2 = new Inet4AddressMatcher("192.168.1.2/32");
    // /32 becomes full mask -> representation is just the IP
    assertEquals("192.168.1.2", m2.getHumanRepresentation());
  }

  @Test
  void getHumanRepresentation_whenMaskBits_expectDottedMask() {
    Inet4AddressMatcher m = new Inet4AddressMatcher("10.1.2.3/24");
    assertEquals("10.1.2.3/255.255.255.0", m.getHumanRepresentation());
  }

  @Test
  void getHumanRepresentation_whenZeroMask_expectDottedZeroMask() {
    Inet4AddressMatcher m = new Inet4AddressMatcher("10.1.2.3/0");
    assertEquals("10.1.2.3/0.0.0.0", m.getHumanRepresentation());
  }

  // ---------- convertToBytes() ----------

  @Test
  void convertToBytes_whenValid_expectCorrectInt() {
    assertEquals(0, Inet4AddressMatcher.convertToBytes("0.0.0.0"));
    assertEquals(-1, Inet4AddressMatcher.convertToBytes("255.255.255.255"));
    int expected = (192 << 24) | (168 << 16) | (1 << 8) | 2;
    assertEquals(expected, Inet4AddressMatcher.convertToBytes("192.168.1.2"));
  }

  @Test
  void convertToBytes_whenTooFewOctets_expectNoSuchElementException() {
    assertThrows(NoSuchElementException.class, () -> Inet4AddressMatcher.convertToBytes("1.2.3"));
  }

  @Test
  void convertToBytes_whenNonNumeric_expectNumberFormatException() {
    assertThrows(NumberFormatException.class, () -> Inet4AddressMatcher.convertToBytes("a.b.c.d"));
  }

  // ---------- Constructor validation (mask bits) ----------

  @Test
  void constructor_whenMaskBitsNegative_expectIllegalArgument() {
    assertThrows(IllegalArgumentException.class, () -> new Inet4AddressMatcher("1.2.3.4/-1"));
  }

  @Test
  void constructor_whenMaskBitsTooLarge_expectIllegalArgument() {
    assertThrows(IllegalArgumentException.class, () -> new Inet4AddressMatcher("1.2.3.4/33"));
  }

  @Test
  void constructor_whenMaskBitsNonNumeric_expectNumberFormatException() {
    assertThrows(NumberFormatException.class, () -> new Inet4AddressMatcher("1.2.3.4/abc"));
  }

  @Test
  void constructor_whenDottedMaskMalformed_expectNoSuchElementException() {
    assertThrows(NoSuchElementException.class, () -> new Inet4AddressMatcher("1.2.3.4/255.0.0"));
  }

  // ---------- helpers ----------

  private static InetAddress addr(String literal) throws UnknownHostException {
    return InetAddress.getAllByName(literal)[0];
  }
}
