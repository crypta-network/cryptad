package network.crypta.runtime.admin;

import java.lang.reflect.Field;
import java.util.Map;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.DarknetPeerNodeStatus;
import network.crypta.node.Node;
import network.crypta.node.NodeStats;
import network.crypta.node.OpennetPeerNodeStatus;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNodeStatus;
import network.crypta.node.PeerStatusBook;
import network.crypta.node.RequestTracker;
import network.crypta.runtime.admin.geoip.GeoIpCountryInfo;
import network.crypta.runtime.admin.geoip.GeoIpCountryLookup;
import network.crypta.runtime.spi.ConnectionsPageKind;
import network.crypta.runtime.spi.ConnectionsPageRequest;
import network.crypta.runtime.spi.ConnectionsPageSnapshot;
import network.crypta.support.BandwidthStatsContainer;
import network.crypta.support.math.RunningAverage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class LegacyConnectionsPagePortTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeStats stats;
  @Mock private PeerManager peers;
  @Mock private PeerStatusBook statusBook;
  @Mock private RequestTracker tracker;
  @Mock private BandwidthStatsContainer bandwidthStats;
  @Mock private GeoIpCountryLookup geoIpCountryLookup;

  private LegacyConnectionsPagePort port;

  @BeforeEach
  void setUp() throws Exception {
    when(node.network().stats()).thenReturn(stats);
    when(node.network().peers()).thenReturn(peers);
    when(node.routing().tracker()).thenReturn(tracker);
    when(peers.statusBook()).thenReturn(statusBook);
    when(node.network().opennet()).thenReturn(null);
    when(node.getStartupTime()).thenReturn(System.currentTimeMillis() - 60_000L);
    when(node.getMyName()).thenReturn("LocalNode");
    when(node.isAdvancedModeEnabled()).thenReturn(false);
    when(node.isFProxyJavascriptEnabled()).thenReturn(false);
    when(node.services()
            .clientCore()
            .getClientLayerPersister()
            .getBandwidthStatsPutter()
            .getLatestBWData())
        .thenReturn(bandwidthStats);
    when(peers.getPeerNodeRoutingBackoffReasons(false)).thenReturn(new String[0]);
    when(peers.getPeerNodeRoutingBackoffReasons(true)).thenReturn(new String[0]);
    when(statusBook.getDarknetPeerNodeStatuses(true)).thenReturn(new DarknetPeerNodeStatus[0]);
    when(statusBook.getDarknetPeerNodeStatuses(false)).thenReturn(new DarknetPeerNodeStatus[0]);
    when(statusBook.getOpennetPeerNodeStatuses(true)).thenReturn(new OpennetPeerNodeStatus[0]);
    when(statusBook.getOpennetPeerNodeStatuses(false)).thenReturn(new OpennetPeerNodeStatus[0]);
    when(statusBook.getPeerNodeStatuses(true)).thenReturn(new PeerNodeStatus[0]);

    setRunningAverage("routingMissDistanceLocal");
    setRunningAverage("routingMissDistanceRemote");
    setRunningAverage("routingMissDistanceOverall");
    setRunningAverage("routingMissDistanceBulk");
    setRunningAverage("routingMissDistanceRT");
    setRunningAverage("backedOffPercent");

    port = new LegacyConnectionsPagePort(node, geoIpCountryLookup);
  }

  @Test
  void render_whenZeroPeers_returnsDetachedSnapshotsForDarknetAndOpennet() {
    ConnectionsPageSnapshot darknet =
        port.render(
            new ConnectionsPageRequest(ConnectionsPageKind.DARKNET, false, false, null, false));
    ConnectionsPageSnapshot opennet =
        port.render(
            new ConnectionsPageRequest(ConnectionsPageKind.OPENNET, false, false, null, false));

    assertEquals(0, darknet.peerCount());
    assertTrue(darknet.peerActionsEnabled());
    assertEquals(0, opennet.peerCount());
    assertFalse(opennet.peerActionsEnabled());
  }

  @Test
  void render_whenAdvancedEnabled_includesOverviewMarkerAbsentFromBasicSnapshot() {
    ConnectionsPageSnapshot basic =
        port.render(
            new ConnectionsPageRequest(ConnectionsPageKind.DARKNET, false, false, null, false));
    ConnectionsPageSnapshot advanced =
        port.render(
            new ConnectionsPageRequest(ConnectionsPageKind.DARKNET, true, false, null, false));

    assertFalse(basic.contentHtmlBeforePeerTable().contains("Node status overview"));
    assertTrue(advanced.contentHtmlBeforePeerTable().contains("Node status overview"));
  }

  @Test
  void render_whenAdvancedBandwidthRendered_usesLocalizedPayloadKeyAndIncludesDetailRows() {
    when(tracker.getNumLocalCHKRequests()).thenReturn(1);
    when(node.network().collector().getTotalIO()).thenReturn(new long[] {6_000L, 3_000L});
    when(stats.getNodeIOStats()).thenReturn(new long[] {0L, 0L, 0L, 600L, 300L, 6_000L});
    when(bandwidthStats.getTotalBytesOut()).thenReturn(12_000L);
    when(bandwidthStats.getTotalBytesIn()).thenReturn(9_000L);

    ConnectionsPageSnapshot snapshot =
        port.render(
            new ConnectionsPageRequest(ConnectionsPageKind.DARKNET, true, false, null, false));

    assertTrue(snapshot.contentHtmlBeforePeerTable().contains("Payload Output"));
    assertFalse(
        snapshot.contentHtmlBeforePeerTable().contains("StatisticsToadlet.payloadOutputSession"));
    assertTrue(
        snapshot.contentHtmlBeforePeerTable().contains("Request output (excluding payload)"));
    assertTrue(snapshot.contentHtmlBeforePeerTable().contains("Total non-request overhead"));
  }

  @Test
  void render_whenMessageTypesEnabled_addsMessageCountMarkup() {
    DarknetPeerNodeStatus peerStatus = mockDarknetStatus("Alpha", "10.0.0.1:1234", 0.25);
    when(peerStatus.getLocalMessagesReceived()).thenReturn(Map.of("CHKData", 2L));
    when(peerStatus.getLocalMessagesSent()).thenReturn(Map.of("CHKData", 1L));
    when(statusBook.getDarknetPeerNodeStatuses(true))
        .thenReturn(new DarknetPeerNodeStatus[] {peerStatus});
    when(statusBook.getDarknetPeerNodeStatuses(false))
        .thenReturn(new DarknetPeerNodeStatus[] {peerStatus});
    when(statusBook.getPeerNodeStatuses(true)).thenReturn(new PeerNodeStatus[] {peerStatus});

    ConnectionsPageSnapshot basic =
        port.render(
            new ConnectionsPageRequest(ConnectionsPageKind.DARKNET, false, false, null, false));
    ConnectionsPageSnapshot detailed =
        port.render(
            new ConnectionsPageRequest(ConnectionsPageKind.DARKNET, false, true, null, false));

    assertFalse(basic.peerTableHtml().contains("message-count"));
    assertTrue(detailed.peerTableHtml().contains("message-count"));
    assertTrue(detailed.peerTableHtml().contains("CHKData"));
  }

  @Test
  void render_whenGeoIpCountryHasFlag_rendersFlagIconMarkupInPeerTable() {
    byte[] peerAddressBytes = new byte[] {10, 0, 0, 1};
    DarknetPeerNodeStatus peerStatus = mockDarknetStatus("Alpha", "10.0.0.1:1234", 0.25);
    when(peerStatus.getPeerAddressBytes()).thenReturn(peerAddressBytes);
    when(statusBook.getDarknetPeerNodeStatuses(true))
        .thenReturn(new DarknetPeerNodeStatus[] {peerStatus});
    when(statusBook.getDarknetPeerNodeStatuses(false))
        .thenReturn(new DarknetPeerNodeStatus[] {peerStatus});
    when(statusBook.getPeerNodeStatuses(true)).thenReturn(new PeerNodeStatus[] {peerStatus});
    when(geoIpCountryLookup.locate(peerAddressBytes))
        .thenReturn(new GeoIpCountryInfo("United States", "/static/icon/flags/us.png"));

    ConnectionsPageSnapshot snapshot =
        port.render(
            new ConnectionsPageRequest(ConnectionsPageKind.DARKNET, false, false, null, false));

    assertTrue(snapshot.peerTableHtml().contains("class=\"flag\""));
    assertTrue(snapshot.peerTableHtml().contains("/static/icon/flags/us.png"));
    assertTrue(snapshot.peerTableHtml().contains("title=\"United States\""));
  }

  @Test
  void render_whenDarknetSortedByName_ordersRowsByRequestedColumn() {
    DarknetPeerNodeStatus bravo = mockDarknetStatus("Bravo", "10.0.0.2:1234", 0.50);
    DarknetPeerNodeStatus alpha = mockDarknetStatus("Alpha", "10.0.0.1:1234", 0.25);
    when(statusBook.getDarknetPeerNodeStatuses(true))
        .thenReturn(new DarknetPeerNodeStatus[] {bravo, alpha});
    when(statusBook.getDarknetPeerNodeStatuses(false))
        .thenReturn(new DarknetPeerNodeStatus[] {bravo, alpha});
    when(statusBook.getPeerNodeStatuses(true)).thenReturn(new PeerNodeStatus[] {bravo, alpha});

    ConnectionsPageSnapshot snapshot =
        port.render(
            new ConnectionsPageRequest(ConnectionsPageKind.DARKNET, false, false, "name", false));

    assertTrue(
        snapshot.peerTableHtml().indexOf("Alpha") < snapshot.peerTableHtml().indexOf("Bravo"));
  }

  @Test
  void render_whenOpennetSortedBySuccessTime_ordersRowsByLastSuccess() throws Exception {
    OpennetPeerNodeStatus older = mockOpennetStatus("10.0.0.5:1234", 1.00, 1_000L);
    OpennetPeerNodeStatus newer = mockOpennetStatus("10.0.0.9:1234", 2.00, 2_000L);
    when(statusBook.getOpennetPeerNodeStatuses(true))
        .thenReturn(new OpennetPeerNodeStatus[] {older, newer});
    when(statusBook.getOpennetPeerNodeStatuses(false))
        .thenReturn(new OpennetPeerNodeStatus[] {older, newer});
    when(statusBook.getPeerNodeStatuses(true)).thenReturn(new PeerNodeStatus[] {older, newer});

    ConnectionsPageSnapshot snapshot =
        port.render(
            new ConnectionsPageRequest(
                ConnectionsPageKind.OPENNET, false, false, "successTime", false));

    assertTrue(
        snapshot.peerTableHtml().indexOf("10.0.0.9:1234")
            < snapshot.peerTableHtml().indexOf("10.0.0.5:1234"));
  }

  private DarknetPeerNodeStatus mockDarknetStatus(
      String name, String address, double selectionRate) {
    DarknetPeerNodeStatus status = mock(DarknetPeerNodeStatus.class);
    stubCommonPeerStatus(status, address, selectionRate, selectionRate);
    when(status.getName()).thenReturn(name);
    when(status.getPrivateDarknetCommentNote()).thenReturn("note");
    when(status.getTrustLevel()).thenReturn(FRIEND_TRUST.NORMAL);
    when(status.getOurVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(status.getTheirVisibility()).thenReturn(FRIEND_VISIBILITY.YES);
    when(status.getLocalMessagesReceived()).thenReturn(Map.of());
    when(status.getLocalMessagesSent()).thenReturn(Map.of());
    return status;
  }

  private OpennetPeerNodeStatus mockOpennetStatus(
      String address, double selectionRate, long timeLastSuccess) throws Exception {
    OpennetPeerNodeStatus status = mock(OpennetPeerNodeStatus.class);
    stubCommonPeerStatus(status, address, selectionRate, selectionRate);
    when(status.getLocalMessagesReceived()).thenReturn(Map.of());
    when(status.getLocalMessagesSent()).thenReturn(Map.of());
    setTimeLastSuccess(status, timeLastSuccess);
    return status;
  }

  private void stubCommonPeerStatus(
      PeerNodeStatus status, String address, double selectionRate, double location) {
    long now = System.currentTimeMillis();
    when(status.getSelectionRate()).thenReturn(selectionRate);
    when(status.getStatusName()).thenReturn("CONNECTED");
    when(status.getStatusCSSName()).thenReturn("connected");
    when(status.getStatusValue()).thenReturn(PeerManager.PEER_NODE_STATUS_CONNECTED);
    when(status.isFetchingARK()).thenReturn(false);
    when(status.getPeerAddress()).thenReturn(address);
    when(status.getPeerAddressAndPort()).thenReturn(address);
    when(status.getPeerAddressBytes()).thenReturn(null);
    when(status.isConnected()).thenReturn(true);
    when(status.getAveragePingTime()).thenReturn(5.0);
    when(status.getAveragePingTimeCorrected()).thenReturn(5.0);
    when(status.isPublicInvalidVersion()).thenReturn(false);
    when(status.isPublicReverseInvalidVersion()).thenReturn(false);
    when(status.getSimpleVersion()).thenReturn(1);
    when(status.isRoutable()).thenReturn(true);
    when(status.getTimeLastRoutable()).thenReturn(now - 1_000L);
    when(status.getTimeLastConnectionCompleted()).thenReturn(now - 1_000L);
    when(status.getPeerAddedTime()).thenReturn(now - 10_000L);
    when(status.getLocation()).thenReturn(location);
    when(status.getPeersLocation()).thenReturn(null);
    when(status.getVersion()).thenReturn("Crypta,1");
    when(status.getBackedOffPercent(true)).thenReturn(0.0);
    when(status.getBackedOffPercent(false)).thenReturn(0.0);
    when(status.getPReject()).thenReturn(0.0);
    when(status.getPercentTimeRoutableConnection()).thenReturn(1.0);
    when(status.getTotalInputBytes()).thenReturn(10L);
    when(status.getTotalOutputBytes()).thenReturn(20L);
    when(status.getTotalInputSinceStartup()).thenReturn(30L);
    when(status.getTotalOutputSinceStartup()).thenReturn(40L);
    when(status.getResendBytesSent()).thenReturn(1L);
    when(status.getClockDelta()).thenReturn(0L);
    when(status.getReportedUptimePercentage()).thenReturn(100);
    when(status.getMessageQueueLengthBytes()).thenReturn(0L);
    when(status.getMessageQueueLengthTime()).thenReturn(0L);
    when(status.getThrottle()).thenReturn(null);
    when(status.getRoutingBackedOffUntil(true)).thenReturn(0L);
    when(status.getRoutingBackedOffUntil(false)).thenReturn(0L);
    when(status.getRoutingBackoffLength(true)).thenReturn(0L);
    when(status.getRoutingBackoffLength(false)).thenReturn(0L);
    when(status.getLastBackoffReason(true)).thenReturn(null);
    when(status.getLastBackoffReason(false)).thenReturn(null);
  }

  private void setTimeLastSuccess(OpennetPeerNodeStatus status, long timestamp) throws Exception {
    Field field = OpennetPeerNodeStatus.class.getField("timeLastSuccess");
    field.setAccessible(true);
    field.setLong(status, timestamp);
  }

  private void setRunningAverage(String fieldName) throws Exception {
    RunningAverage runningAverage = mock(RunningAverage.class);
    when(runningAverage.currentValue()).thenReturn(0.0);
    Field field = NodeStats.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(stats, runningAverage);
  }
}
