package network.crypta.node.runtime;

import java.net.InetAddress;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.io.AddressTracker;
import network.crypta.io.InetAddressAddressTrackerItem;
import network.crypta.io.PeerAddressTrackerItem;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.node.Node;
import network.crypta.node.NodeIPDetector;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.spi.ConnectivityListenerPortSnapshot;
import network.crypta.runtime.spi.ConnectivityNoticeSnapshot;
import network.crypta.runtime.spi.ConnectivityPortForwardStatus;
import network.crypta.runtime.spi.ConnectivitySnapshot;
import network.crypta.runtime.spi.ConnectivitySocketSnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficEntrySnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficInitiator;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class LegacyConnectivityPortTest {

  @Mock private Node node;
  @Mock private NodeNetworkSubsystem network;
  @Mock private PersistentConfig config;
  @Mock private NodeIPDetector ipDetector;

  private LegacyConnectivityPort port;

  @BeforeEach
  void setUp() {
    port = new LegacyConnectivityPort(node);
    when(node.network()).thenReturn(network);
    when(node.getConfig()).thenReturn(config);
    when(network.ipDetector()).thenReturn(ipDetector);
    when(network.packetSocketHandlers()).thenReturn(new UdpSocketHandler[0]);
    when(network.fnpPort()).thenReturn(12345);
    when(network.opennetFnpPort()).thenReturn(33333);
  }

  @Test
  void snapshot_whenCalled_mapsPortNumbersAndListenerConfig() {
    setConfigPorts(true, 8080, 9481, true, 2222);

    ConnectivitySnapshot snapshot = port.snapshot(false);

    assertEquals(12345, snapshot.darknetFnpPort());
    assertEquals(33333, snapshot.opennetFnpPort());
    assertEquals(new ConnectivityListenerPortSnapshot(true, 8080), snapshot.fproxyListener());
    assertEquals(new ConnectivityListenerPortSnapshot(false, 0), snapshot.fcpListener());
    assertEquals(new ConnectivityListenerPortSnapshot(true, 2222), snapshot.consoleListener());
    assertNull(snapshot.connectionTypeNotice());
  }

  @ParameterizedTest
  @EnumSource(AddressTracker.Status.class)
  void snapshot_whenSocketStatusPresent_mapsLegacyStatus(AddressTracker.Status status) {
    setConfigPorts(false, 0, 0, false, 0);
    AddressTracker tracker = mock(AddressTracker.class);
    when(tracker.getPortForwardStatus()).thenReturn(status);

    UdpSocketHandler handler = mock(UdpSocketHandler.class);
    when(handler.getTitle()).thenReturn("udp-9999");
    when(handler.getAddressTracker()).thenReturn(tracker);
    when(network.packetSocketHandlers()).thenReturn(new UdpSocketHandler[] {handler});

    ConnectivitySnapshot snapshot = port.snapshot(false);

    assertEquals(expectedStatus(status), snapshot.sockets().getFirst().portForwardStatus());
  }

  @Test
  void snapshot_whenAdvancedDetailsDisabled_skipsTrackerTableExport() {
    setConfigPorts(false, 0, 0, false, 0);
    AddressTracker tracker = mock(AddressTracker.class);
    when(tracker.getPortForwardStatus()).thenReturn(AddressTracker.Status.DONT_KNOW);

    UdpSocketHandler handler = mock(UdpSocketHandler.class);
    when(handler.getTitle()).thenReturn("udp-9999");
    when(handler.getAddressTracker()).thenReturn(tracker);
    when(network.packetSocketHandlers()).thenReturn(new UdpSocketHandler[] {handler});

    ConnectivitySocketSnapshot summaryOnly = port.snapshot(false).sockets().getFirst();

    assertEquals(-1, summaryOnly.longestSendReceiveGapMillis());
    assertTrue(summaryOnly.peerEntries().isEmpty());
    assertTrue(summaryOnly.ipEntries().isEmpty());
    verify(tracker, never()).getLongestSendReceiveGap();
    verify(tracker, never()).getPeerAddressTrackerItems();
    verify(tracker, never()).getInetAddressTrackerItems();

    clearInvocations(tracker);
    when(tracker.getLongestSendReceiveGap()).thenReturn(12_345L);
    when(tracker.getPeerAddressTrackerItems()).thenReturn(new PeerAddressTrackerItem[0]);
    when(tracker.getInetAddressTrackerItems()).thenReturn(new InetAddressAddressTrackerItem[0]);

    ConnectivitySocketSnapshot withAdvanced = port.snapshot(true).sockets().getFirst();

    assertEquals(12_345L, withAdvanced.longestSendReceiveGapMillis());
    verify(tracker).getLongestSendReceiveGap();
    verify(tracker).getPeerAddressTrackerItems();
    verify(tracker).getInetAddressTrackerItems();
  }

  @Test
  void snapshot_whenAdvancedDetailsEnabled_mapsTrackerRowsAndGaps() throws Exception {
    setConfigPorts(false, 0, 0, false, 0);
    PeerAddressTrackerItem peerItem =
        new PeerAddressTrackerItem(0, 0, new Peer("1.1.1.1:4242", false));
    peerItem.sentPacket(1_000L);
    peerItem.receivedPacket(AddressTracker.MAYBE_TUNNEL_LENGTH + 2_000L);

    InetAddressAddressTrackerItem ipItem =
        new InetAddressAddressTrackerItem(0, 0, InetAddress.getByName("2.2.2.2"));
    ipItem.receivedPacket(2_000L);
    ipItem.sentPacket(AddressTracker.MAYBE_TUNNEL_LENGTH + 4_000L);

    AddressTracker tracker = mock(AddressTracker.class);
    when(tracker.getPortForwardStatus())
        .thenReturn(AddressTracker.Status.DEFINITELY_PORT_FORWARDED);
    when(tracker.getLongestSendReceiveGap()).thenReturn(12_345L);
    when(tracker.getPeerAddressTrackerItems()).thenReturn(new PeerAddressTrackerItem[] {peerItem});
    when(tracker.getInetAddressTrackerItems())
        .thenReturn(new InetAddressAddressTrackerItem[] {ipItem});

    UdpSocketHandler handler = mock(UdpSocketHandler.class);
    when(handler.getTitle()).thenReturn("udp-9999");
    when(handler.getAddressTracker()).thenReturn(tracker);
    when(network.packetSocketHandlers()).thenReturn(new UdpSocketHandler[] {handler});

    ConnectivitySocketSnapshot socket = port.snapshot(true).sockets().getFirst();

    assertEquals(12_345L, socket.longestSendReceiveGapMillis());
    assertEquals(
        ConnectivityPortForwardStatus.DEFINITELY_PORT_FORWARDED, socket.portForwardStatus());

    ConnectivityTrafficEntrySnapshot peerEntry = socket.peerEntries().getFirst();
    assertEquals("1.1.1.1:4242", peerEntry.address());
    assertEquals(1, peerEntry.packetsSent());
    assertEquals(1, peerEntry.packetsReceived());
    assertEquals(ConnectivityTrafficInitiator.LOCAL, peerEntry.initiator());
    assertEquals(5, peerEntry.gaps().size());
    assertTrue(peerEntry.gaps().getFirst().gapLengthMillis() > 0);
    assertTrue(peerEntry.gaps().getFirst().receivedPacketAtMillis() > 0);

    ConnectivityTrafficEntrySnapshot ipEntry = socket.ipEntries().getFirst();
    assertEquals("/2.2.2.2", ipEntry.address());
    assertEquals(ConnectivityTrafficInitiator.REMOTE, ipEntry.initiator());
  }

  @Test
  void snapshot_whenConnectionTypeNoticePresent_exportsDetachedNotice() {
    setConfigPorts(false, 0, 0, false, 0);
    ConnectivityNoticeSnapshot notice =
        new ConnectivityNoticeSnapshot(
            "Connection Type",
            "Port restricted NAT detected",
            "<div class=\"infobox infobox-warning\">notice</div>");
    when(ipDetector.connectionTypeNotice()).thenReturn(notice);

    ConnectivitySnapshot snapshot = port.snapshot(false);

    assertEquals(notice, snapshot.connectionTypeNotice());
  }

  private ConnectivityPortForwardStatus expectedStatus(AddressTracker.Status status) {
    return switch (status) {
      case DEFINITELY_NATED -> ConnectivityPortForwardStatus.DEFINITELY_NATED;
      case MAYBE_NATED -> ConnectivityPortForwardStatus.MAYBE_NATED;
      case DONT_KNOW -> ConnectivityPortForwardStatus.DONT_KNOW;
      case MAYBE_PORT_FORWARDED -> ConnectivityPortForwardStatus.MAYBE_PORT_FORWARDED;
      case DEFINITELY_PORT_FORWARDED -> ConnectivityPortForwardStatus.DEFINITELY_PORT_FORWARDED;
    };
  }

  private void setConfigPorts(
      boolean fproxyEnabled, int fproxyPort, int fcpPort, boolean tmciEnabled, int tmciPort) {
    when(config.get("fproxy")).thenReturn(mockSubConfig(fproxyEnabled, fproxyPort));
    when(config.get("fcp")).thenReturn(mockSubConfig(false, fcpPort));
    when(config.get("console")).thenReturn(mockSubConfig(tmciEnabled, tmciPort));
  }

  private SubConfig mockSubConfig(boolean enabled, int portNumber) {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.put("enabled", enabled);
    fieldSet.put("port", portNumber);
    return mock(
        SubConfig.class,
        invocation -> {
          if ("exportFieldSet".equals(invocation.getMethod().getName())) {
            return fieldSet;
          }
          return org.mockito.Answers.RETURNS_DEFAULTS.answer(invocation);
        });
  }
}
