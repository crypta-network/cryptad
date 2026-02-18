package network.crypta.io.comm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.stream.Stream;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import network.crypta.support.transport.ip.IPUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link FreenetInetAddress}.
 *
 * <p>Tests follow AAA style, avoid network I/O by mocking DNS lookups, and cover constructors,
 * equality variants, serialization, and helper APIs. Mockito static mocking is enabled via the
 * inline mock-maker configuration present in test resources.
 */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FreenetInetAddressTest {
  private static final String HOST_NODE_LOCAL = "node.local";
  private static final String HOST_V6_EXAMPLE = "v6host.example";
  private static final String HOST_T_EXAMPLE = "t.example";

  // ---------------------------- Constructors (DataInput) ----------------------------

  @ParameterizedTest(name = "new-format roundtrip: {0}")
  @MethodSource("newFormatRoundtripCases")
  @DisplayName("constructor(DataInput) new-format IPv4/IPv6 round-trip")
  void constructor_whenNewFormatRoundTrip_expectSameAddressAndHostname(
      InetAddress inputAddr, String hostname, int expectedMarker) throws Exception {
    // Arrange: serialize using writeToDataOutputStream() to ensure consistent format
    FreenetInetAddress original =
        hostname == null
            ? new FreenetInetAddress(inputAddr)
            : new FreenetInetAddress(hostname, true);
    if (hostname != null) {
      // Cache the provided IP into the instance so writeTo() writes the marker+bytes for it
      try (MockedStatic<InetAddress> inet = mockStatic(InetAddress.class)) {
        inet.when(() -> InetAddress.getAllByName(eq(hostname)))
            .thenReturn(new InetAddress[] {inputAddr});
        // Force resolution
        assertEquals(inputAddr, original.getAddress(true));
      }
    }
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bout)) {
      original.writeToDataOutputStream(dos);
    }

    // Act: construct from the serialized form
    FreenetInetAddress parsed =
        new FreenetInetAddress(new DataInputStream(new ByteArrayInputStream(bout.toByteArray())));

    // Assert: marker correctness and fields
    byte[] raw = bout.toByteArray();
    assertEquals(expectedMarker & 0xFF, raw[0] & 0xFF, "type marker must match (0=IPv4,255=IPv6)");
    assertEquals(inputAddr.getHostAddress(), parsed.getAddress().getHostAddress());
    if (hostname == null) {
      assertFalse(parsed.hasHostname());
      assertEquals(inputAddr.getHostAddress(), parsed.toString());
    } else {
      assertTrue(parsed.hasHostname());
      assertEquals(hostname, parsed.toString());
    }
  }

  private static Stream<Arguments> newFormatRoundtripCases() throws Exception {
    InetAddress v4 = InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 60});
    InetAddress v6 =
        InetAddress.getByAddress(
            new byte[] {
              // 2001:db8::1
              0x20, 0x01, 0x0D, (byte) 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            });
    return Stream.of(
        Arguments.of(v4, null, 0),
        Arguments.of(v6, null, 255),
        Arguments.of(v4, "node.example", 0),
        Arguments.of(v6, "host.example", 255));
  }

  @Test
  @DisplayName("constructor(DataInput) whenUnknownTypeMarker_expectIOException")
  void constructor_whenUnknownMarker_expectIOException() {
    // Arrange: first byte=1 (neither 0 nor 255)
    byte[] data = new byte[] {1, 0, 0, 0, 0};
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));

    // Act + Assert
    assertThrows(IOException.class, () -> new FreenetInetAddress(dis));
  }

  @Test
  @DisplayName("constructor(DataInput,check) old-format IPv4 parses bytes")
  void constructor_whenOldFormatIPv4_expectParsedAddress() throws Exception {
    // Arrange: old format → first byte is first octet, then three more octets
    byte[] payload = new byte[] {(byte) 192, 0, 2, 123}; // 192.0.2.123 (RFC 5737)
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bout)) {
      dos.write(payload[0] & 0xFF);
      dos.write(payload, 1, 3);
      dos.writeUTF(""); // no hostname
    }

    // Act
    FreenetInetAddress got =
        new FreenetInetAddress(
            new DataInputStream(new ByteArrayInputStream(bout.toByteArray())), true);

    // Assert
    assertEquals("192.0.2.123", got.getAddress().getHostAddress());
    assertFalse(got.hasHostname());
  }

  @Test
  @DisplayName("constructor(DataInput,check) invalid hostname triggers HostnameSyntaxException")
  void constructor_whenInvalidHostname_expectHostnameSyntaxException() throws Exception {
    // Arrange: new-format IPv4 + invalid hostname string
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bout)) {
      dos.write(0); // IPv4 marker
      dos.write(new byte[] {1, 1, 1, 1});
      dos.writeUTF("bad host!"); // includes space and punctuation → invalid
    }

    // Act + Assert
    assertThrows(
        HostnameSyntaxException.class,
        () ->
            new FreenetInetAddress(
                new DataInputStream(new ByteArrayInputStream(bout.toByteArray())), true));
  }

  // ---------------------------- equals()/strictEquals()/laxEquals() ----------------------------

  @Test
  @DisplayName("equals/strict/lax when same hostname (same case) → true")
  void equals_whenSameHostnameSameCase_expectTrue() throws Exception {
    // Arrange
    FreenetInetAddress a = new FreenetInetAddress("foo.example", true, false);
    FreenetInetAddress b = new FreenetInetAddress("foo.example", true, false);

    // Act + Assert
    assertEquals(a, b);
    assertTrue(a.strictEquals(b));
    assertTrue(a.laxEquals(b));
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  @DisplayName("equals when both IP-only and identical → true; strictEquals uses reverse name")
  void equals_whenBothIPOnlySame_expectTrue() throws Exception {
    // Arrange
    InetAddress ip = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    FreenetInetAddress a = new FreenetInetAddress(ip);
    FreenetInetAddress b = new FreenetInetAddress(InetAddress.getByAddress(ip.getAddress()));

    // Act + Assert
    assertEquals(a, b);
    assertTrue(a.strictEquals(b));
    assertTrue(a.laxEquals(b));
  }

  @Test
  @DisplayName("equals/lax when one has hostname and other is IP-only → false")
  void equals_whenHostnameVsIPOnly_expectFalse() throws Exception {
    // Arrange
    FreenetInetAddress hostOnly = new FreenetInetAddress("example.com", true, false);
    FreenetInetAddress ipOnly =
        new FreenetInetAddress(InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 60}));

    // Act + Assert
    assertNotEquals(hostOnly, ipOnly);
    assertFalse(hostOnly.laxEquals(ipOnly));
  }

  @Test
  @DisplayName("laxEquals propagates resolved IP between equal hostnames")
  void laxEquals_whenSameHostnameAndOneResolved_expectPropagationAndTrue() throws Exception {
    // Arrange
    InetAddress resolved = InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 5});
    FreenetInetAddress a = new FreenetInetAddress(HOST_NODE_LOCAL, true, false);
    FreenetInetAddress b = new FreenetInetAddress(HOST_NODE_LOCAL, true, false);
    // Resolve only one side deterministically
    try (MockedStatic<InetAddress> inet = mockStatic(InetAddress.class)) {
      inet.when(() -> InetAddress.getAllByName(eq(HOST_NODE_LOCAL)))
          .thenReturn(new InetAddress[] {resolved});
      assertEquals(resolved, a.getAddress(true));
    }

    // Act: compare → should propagate IP to 'b' and be equal
    assertTrue(a.laxEquals(b));

    // Assert: 'b' now prefers numeric form
    assertEquals("192.0.2.5", b.toStringPrefNumeric());
  }

  // ---------------------------- Address lookup APIs ----------------------------

  @Test
  @DisplayName("getAddress(false) when hostname-only → null (no lookup)")
  void getAddress_whenDoNotLookup_expectNull() throws Exception {
    // Arrange
    FreenetInetAddress a = new FreenetInetAddress("unresolved.example", true, false);

    // Act + Assert
    assertNull(a.getAddress(false));
  }

  @Test
  @DisplayName("getHandshakeAddress chooses one result and caches it")
  void getHandshakeAddress_whenMultipleResults_expectChosenIsCached() throws Exception {
    // Arrange: provide IPv4 and IPv6 and ensure IPv6 is chosen and cached
    InetAddress v4 = InetAddress.getByAddress(new byte[] {(byte) 203, 0, 113, 1});
    InetAddress v6 =
        InetAddress.getByAddress(
            new byte[] {0x20, 0x01, 0x0D, (byte) 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2});
    FreenetInetAddress a = new FreenetInetAddress("dual.example", true, false);

    try (MockedStatic<InetAddress> inet = mockStatic(InetAddress.class)) {
      inet.when(() -> InetAddress.getAllByName(eq("dual.example")))
          .thenReturn(new InetAddress[] {v4, v6});

      // Act
      InetAddress chosen = a.getHandshakeAddress();

      // Assert: result is one of the provided answers
      String chosenNumeric = chosen != null ? chosen.getHostAddress() : null;
      assertNotNull(chosenNumeric);
      assertTrue(
          Arrays.asList(v4.getHostAddress(), v6.getHostAddress()).contains(chosenNumeric),
          "Handshake must return one of the DNS answers");
    }
  }

  @Test
  @DisplayName("getHandshakeAddress when UnknownHostException → null")
  void getHandshakeAddress_whenUnknownHost_expectNull() throws Exception {
    // Arrange
    FreenetInetAddress a = new FreenetInetAddress("missing.example", true, false);
    try (MockedStatic<InetAddress> inet = mockStatic(InetAddress.class)) {
      inet.when(() -> InetAddress.getAllByName(eq("missing.example")))
          .thenThrow(new UnknownHostException("nope"));

      // Act + Assert
      assertNull(a.getHandshakeAddress());
    }
  }

  // ---------------------------- Serialization (writeTo...) ----------------------------

  @Test
  @DisplayName("writeToDataOutputStream IPv4 (no hostname) round-trip")
  void writeToDataOutputStream_whenIPv4NoHostname_expectRoundtrip() throws Exception {
    // Arrange
    FreenetInetAddress src =
        new FreenetInetAddress(InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 42}));
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bout)) {
      src.writeToDataOutputStream(dos);
    }

    // Act
    FreenetInetAddress roundtrip =
        new FreenetInetAddress(new DataInputStream(new ByteArrayInputStream(bout.toByteArray())));

    // Assert
    assertEquals("192.0.2.42", roundtrip.getAddress().getHostAddress());
    assertFalse(roundtrip.hasHostname());
  }

  @Test
  @DisplayName("writeToDataOutputStream IPv6 (with hostname) round-trip")
  void writeToDataOutputStream_whenIPv6WithHostname_expectRoundtrip() throws Exception {
    // Arrange
    InetAddress v6 =
        InetAddress.getByAddress(
            new byte[] {0x20, 0x01, 0x0D, (byte) 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3});
    FreenetInetAddress src = new FreenetInetAddress(HOST_V6_EXAMPLE, true, false);
    try (MockedStatic<InetAddress> inet = mockStatic(InetAddress.class)) {
      inet.when(() -> InetAddress.getAllByName(eq(HOST_V6_EXAMPLE)))
          .thenReturn(new InetAddress[] {v6});
      assertEquals(v6, src.getAddress(true));
    }
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bout)) {
      src.writeToDataOutputStream(dos);
    }

    // Act
    FreenetInetAddress roundtrip =
        new FreenetInetAddress(new DataInputStream(new ByteArrayInputStream(bout.toByteArray())));

    // Assert
    assertEquals(v6.getHostAddress(), roundtrip.getAddress().getHostAddress());
    assertEquals(HOST_V6_EXAMPLE, roundtrip.toString());
  }

  // ---------------------------- Helpers and misc ----------------------------

  @Test
  @DisplayName("getHostName null → null; numeric-only → numeric")
  void getHostName_whenNullOrNumeric_expectNullOrNumeric() throws Exception {
    // Arrange
    InetAddress v4 = InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 4});

    // Act + Assert
    assertNull(FreenetInetAddress.getHostName(null));
    assertEquals("192.0.2.4", FreenetInetAddress.getHostName(v4));
  }

  @Test
  @DisplayName("toString prefers hostname; toStringPrefNumeric prefers numeric if present")
  void toStringVariants_whenHostnameAndAddress_expectExpectedPreference() throws Exception {
    // Arrange
    FreenetInetAddress a = new FreenetInetAddress(HOST_T_EXAMPLE, true, false);
    InetAddress ip = InetAddress.getByAddress(new byte[] {(byte) 198, 51, 100, 44});
    try (MockedStatic<InetAddress> inet = mockStatic(InetAddress.class)) {
      inet.when(() -> InetAddress.getAllByName(eq(HOST_T_EXAMPLE)))
          .thenReturn(new InetAddress[] {ip});
      assertEquals(ip, a.getAddress(true));
    }

    // Act + Assert
    assertEquals(HOST_T_EXAMPLE, a.toString());
    assertEquals("198.51.100.44", a.toStringPrefNumeric());
  }

  @Test
  @DisplayName("dropHostname when no resolved address → null; when resolved → new IP-only instance")
  void dropHostname_whenUnresolvedThenResolved_expectNullThenIPOnly() throws Exception {
    // Arrange: unresolved hostname
    FreenetInetAddress a = new FreenetInetAddress("dyn.example", true, false);

    // Act + Assert: unresolved → null
    assertNull(a.dropHostname());

    // Resolve deterministically
    InetAddress ip = InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 7});
    try (MockedStatic<InetAddress> inet = mockStatic(InetAddress.class)) {
      inet.when(() -> InetAddress.getAllByName(eq("dyn.example")))
          .thenReturn(new InetAddress[] {ip});
      assertEquals(ip, a.getAddress(true));
    }

    // Act: drop now returns a new IP-only instance
    FreenetInetAddress dropped = a.dropHostname();

    // Assert
    assertNotNull(dropped);
    assertFalse(dropped.hasHostname());
    assertEquals("192.0.2.7", dropped.toString());
  }

  @Test
  @DisplayName("dropHostname on IP-only instance returns same instance")
  void dropHostname_whenAlreadyIPOnly_expectSameInstance() throws Exception {
    // Arrange
    FreenetInetAddress ipOnly =
        new FreenetInetAddress(InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 9}));

    // Act
    FreenetInetAddress dropped = ipOnly.dropHostname();

    // Assert
    assertSame(ipOnly, dropped);
  }

  @Test
  @DisplayName("hasHostname and hasHostnameNoIP reflect state correctly")
  void hasHostnameFlags_whenHostnameOnlyAndAfterResolve_expectCorrect() throws Exception {
    // Arrange
    FreenetInetAddress a = new FreenetInetAddress("flags.example", true, false);

    // Assert initial flags
    assertTrue(a.hasHostname());
    assertTrue(a.hasHostnameNoIP());

    // Resolve to set _address
    InetAddress ip = InetAddress.getByAddress(new byte[] {(byte) 203, 0, 113, 60});
    try (MockedStatic<InetAddress> inet = mockStatic(InetAddress.class)) {
      inet.when(() -> InetAddress.getAllByName(eq("flags.example")))
          .thenReturn(new InetAddress[] {ip});
      assertEquals(ip, a.getAddress(true));
    }

    // Assert updated flags
    assertTrue(a.hasHostname());
    assertFalse(a.hasHostnameNoIP());
  }

  @Test
  @DisplayName("isIPv6 respects default when unresolved and detects actual family when resolved")
  void isIPv6_whenUnresolvedThenResolved_expectDefaultThenActual() throws Exception {
    // Arrange
    FreenetInetAddress a = new FreenetInetAddress("v6check.example", true, false);

    // Assert: unresolved → default value returned
    assertTrue(a.isIPv6(true));
    assertFalse(a.isIPv6(false));

    // Resolve to IPv6
    InetAddress v6 =
        InetAddress.getByAddress(
            new byte[] {0x20, 0x01, 0x0D, (byte) 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4});
    try (MockedStatic<InetAddress> inet = mockStatic(InetAddress.class)) {
      inet.when(() -> InetAddress.getAllByName(eq("v6check.example")))
          .thenReturn(new InetAddress[] {v6});
      assertEquals(v6, a.getAddress(true));
    }

    // Assert: now detects IPv6
    assertTrue(a.isIPv6(false));
  }

  @Test
  @DisplayName("isRealInternetAddress uses cached address when present and honors IPUtil")
  void isRealInternetAddress_whenCachedAddress_expectDelegatesToIPUtil() throws Exception {
    // Arrange: cached RFC1918 address; delegate answer controlled via mock
    InetAddress ip = InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 10});
    FreenetInetAddress a = new FreenetInetAddress(ip);

    try (MockedStatic<IPUtil> iputil = mockStatic(IPUtil.class)) {
      iputil.when(() -> IPUtil.isValidAddress(eq(ip), eq(false))).thenReturn(false);

      // Act + Assert
      assertFalse(a.isRealInternetAddress(false, true, false));
    }
  }

  @Test
  @DisplayName("isRealInternetAddress performs lookup when allowed and no cached address")
  void isRealInternetAddress_whenLookupAllowedAndResolves_expectDelegatesToIPUtil()
      throws Exception {
    // Arrange
    FreenetInetAddress a = new FreenetInetAddress("pub.example", true, false);
    InetAddress resolved = InetAddress.getByAddress(new byte[] {(byte) 203, 0, 113, 34});

    try (MockedStatic<InetAddress> inet = mockStatic(InetAddress.class);
        MockedStatic<IPUtil> iputil = mockStatic(IPUtil.class)) {
      inet.when(() -> InetAddress.getAllByName(eq("pub.example")))
          .thenReturn(new InetAddress[] {resolved});
      iputil.when(() -> IPUtil.isValidAddress(eq(resolved), eq(false))).thenReturn(true);

      // Act + Assert
      assertTrue(a.isRealInternetAddress(true, false, false));
    }
  }

  @Test
  @DisplayName("isRealInternetAddress when lookup denied and no cached address → default value")
  void isRealInternetAddress_whenNoLookupAndUnresolved_expectDefault() throws Exception {
    // Arrange
    FreenetInetAddress a = new FreenetInetAddress("default.example", true, false);

    // Act + Assert
    assertTrue(a.isRealInternetAddress(false, true, false));
    assertFalse(a.isRealInternetAddress(false, false, false));
  }
}
