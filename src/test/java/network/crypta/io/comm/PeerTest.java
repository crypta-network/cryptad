package network.crypta.io.comm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import network.crypta.io.comm.Peer.LocalAddressException;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PeerTest {

  private static final String LOOPBACK = "127.0.0.1";
  private static final String IPV4_ENDPOINT = "192.0.2.1:1234";
  private static final String DOC_IP_EQUAL = "203.0.113.22";

  @Test
  @SuppressWarnings("java:S100")
  void constructor_inetAddress_withInvalidPort_throwsIllegalArgumentException() throws Exception {
    InetAddress ip = literal(LOOPBACK);
    assertThrows(IllegalArgumentException.class, () -> new Peer(ip, -1));
    assertThrows(IllegalArgumentException.class, () -> new Peer(ip, 65536));
  }

  @Test
  @SuppressWarnings("java:S100")
  void constructor_freenetInetAddress_null_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new Peer((FreenetInetAddress) null, 80));
  }

  @Test
  @SuppressWarnings("java:S100")
  void constructor_dataInput_withInvalidPort_throwsIOException() throws Exception {
    // Prepare a serialized FreenetInetAddress (IPv4 127.0.0.1, empty hostname)
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bout)) {
      FreenetInetAddress addr = new FreenetInetAddress(literal(LOOPBACK));
      addr.writeToDataOutputStream(dos);
      dos.writeInt(99999); // invalid port (> 65535)
    }
    byte[] bytes = bout.toByteArray();

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      assertThrows(IOException.class, () -> new Peer(dis));
    }
  }

  @Test
  @SuppressWarnings("java:S100")
  void constructor_string_ipv4_parsesSuccessfully() throws Exception {
    Peer p = new Peer(IPV4_ENDPOINT, true);
    assertEquals(1234, p.getPort());
    assertEquals(IPV4_ENDPOINT, p.toString());
    assertEquals(IPV4_ENDPOINT, p.toStringPrefNumeric());
    assertNotNull(p.getAddress());
  }

  @Test
  @SuppressWarnings("java:S100")
  void constructor_string_missingPort_throwsPeerParseException() {
    assertThrows(PeerParseException.class, () -> new Peer("example.invalid", true));
  }

  @Test
  @SuppressWarnings("java:S100")
  void constructor_string_invalidPort_throwsPeerParseException() {
    assertThrows(PeerParseException.class, () -> new Peer("example.invalid:abc", true));
    assertThrows(PeerParseException.class, () -> new Peer("example.invalid:70000", true));
  }

  @Test
  @SuppressWarnings("java:S100")
  void constructor_string_withSyntaxCheck_invalidHostname_throwsHostnameSyntaxException() {
    assertThrows(HostnameSyntaxException.class, () -> new Peer("inv@lid.host:1234", true, true));
  }

  @Test
  @SuppressWarnings("java:S100")
  void isNull_whenPortZero_trueOtherwiseFalse() throws Exception {
    Peer p1 = new Peer(literal("192.0.2.10"), 0);
    Peer p2 = new Peer(literal("192.0.2.10"), 80);
    assertTrue(p1.isNull());
    assertFalse(p2.isNull());
  }

  @Test
  @SuppressWarnings("java:S100")
  void getAddress_localDisallowed_throwsLocalAddressException() throws Exception {
    Peer p = new Peer(literal(LOOPBACK), 1);
    assertThrows(LocalAddressException.class, () -> p.getAddress(true, false));
    // Allowed when flag is true
    InetAddress a = p.getAddress(true, true);
    assertEquals(LOOPBACK, a.getHostAddress());
  }

  @Test
  @SuppressWarnings("java:S100")
  void getAddress_doNotLookup_returnsNullWhenUnresolved() throws Exception {
    Peer p = new Peer("nonexistent.invalid:9999", true);
    assertNull(p.getAddress(false));
  }

  @Test
  @SuppressWarnings("java:S100")
  void dropHostName_whenUnresolved_returnsNull() throws PeerParseException, UnknownHostException {
    Peer p = new Peer("example.invalid:8080", true);
    assertNull(p.dropHostName());
  }

  @Test
  @SuppressWarnings("java:S100")
  void dropHostName_whenAlreadyIpOnly_returnsSameInstance() throws Exception {
    Peer p = new Peer(literal("198.51.100.10"), 4242);
    Peer dropped = p.dropHostName();
    assertSame(p, dropped, "Expected the same instance");
  }

  @Test
  @SuppressWarnings("java:S100")
  void dropHostName_whenHostnameAndResolved_returnsNewPeerWithIpOnly() throws Exception {
    FreenetInetAddress withHostname = mock(FreenetInetAddress.class);
    when(withHostname.dropHostname()).thenReturn(new FreenetInetAddress(literal("198.51.100.20")));
    Peer p = new Peer(withHostname, 443);
    Peer dropped = p.dropHostName();
    assertNotSame(p, dropped);
    assertEquals(443, dropped.getPort());
    assertFalse(dropped.getFreenetAddress().hasHostname());
    assertEquals("198.51.100.20:443", dropped.toString());
  }

  @Test
  @SuppressWarnings("java:S100")
  void equals_whenHostnamesDifferOnlyByCase_true() throws Exception {
    Peer p1 = new Peer("Example.COM:80", true);
    Peer p2 = new Peer("example.com:80", true);
    assertEquals(p1, p2);
  }

  @Test
  @SuppressWarnings("java:S100")
  void laxEquals_whenSameIpAndPort_true() throws Exception {
    Peer p1 = new Peer(literal("203.0.113.10"), 1111);
    Peer p2 = new Peer(literal("203.0.113.10"), 1111);
    assertTrue(p1.laxEquals(p2));
  }

  @Test
  @SuppressWarnings("java:S100")
  void strictEquals_whenSameNumericIp_true() throws Exception {
    Peer p1 = new Peer(literal(DOC_IP_EQUAL), 7);
    Peer p2 = new Peer(literal(DOC_IP_EQUAL), 7);
    assertTrue(p1.strictEquals(p2));
  }

  @Test
  @SuppressWarnings("java:S100")
  void strictEquals_whenDifferentNumericIp_false() throws Exception {
    Peer p1 = new Peer(literal(DOC_IP_EQUAL), 7);
    Peer p2 = new Peer(literal("203.0.113.23"), 7);
    assertFalse(p1.strictEquals(p2));
  }

  @Test
  @SuppressWarnings("java:S100")
  @DisplayName("PeerComparator: hostname < no-hostname")
  void comparator_prefersHostnameBeforeIpOnly() throws Exception {
    Peer withHost = new Peer("example.invalid:9999", true);
    Peer ipOnly = new Peer(literal("203.0.113.1"), 9999);
    assertTrue(Peer.PEER_COMPARATOR.compare(withHost, ipOnly) < 0);
    assertTrue(Peer.PEER_COMPARATOR.compare(ipOnly, withHost) > 0);
  }

  @Test
  @SuppressWarnings("java:S100")
  @DisplayName("PeerComparator: both hostnames => 0")
  void comparator_bothHostnames_returnsZero() throws Exception {
    Peer h1 = new Peer("example.invalid:9999", true);
    Peer h2 = new Peer("example.invalid:8888", true);
    assertEquals(0, Peer.PEER_COMPARATOR.compare(h1, h2));
  }

  @Test
  @SuppressWarnings("java:S100")
  @DisplayName("PeerComparator: IPv6 preferred over IPv4")
  void comparator_prefersIpv6OverIpv4() throws Exception {
    Inet6Address v6 = (Inet6Address) literal("2001:db8::1");
    InetAddress v4 = literal("203.0.113.100");
    Peer p6 = new Peer(v6, 65000);
    Peer p4 = new Peer(v4, 65000);
    assertTrue(Peer.PEER_COMPARATOR.compare(p6, p4) < 0);
  }

  @Test
  @SuppressWarnings("java:S100")
  void writeAndRead_roundTrip_preservesEqualityAndHashCode() throws Exception {
    Peer original = new Peer(literal("198.51.100.30"), 3210);
    byte[] serialized;
    try (ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bout)) {
      original.writeToDataOutputStream(dos);
      serialized = bout.toByteArray();
    }

    Peer restored;
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(serialized))) {
      restored = new Peer(dis);
    }

    assertEquals(original, restored);
    assertEquals(original.hashCode(), restored.hashCode());
    assertEquals(original.toString(), restored.toString());
  }

  private static InetAddress literal(String host) throws UnknownHostException {
    return InetAddress.getAllByName(host)[0];
  }
}
