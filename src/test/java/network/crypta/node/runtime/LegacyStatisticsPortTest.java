package network.crypta.node.runtime;

import java.lang.reflect.Field;
import java.util.Map;
import network.crypta.client.async.ClientBaseCallback;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetState;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.PersistentStatsPutter;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeStats;
import network.crypta.node.NodeStatsHtmlRenderer;
import network.crypta.node.PeerManager;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestTracker;
import network.crypta.runtime.spi.StatisticsPageSnapshot;
import network.crypta.support.BandwidthStatsContainer;
import network.crypta.support.HTMLNode;
import network.crypta.support.math.RunningAverage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class LegacyStatisticsPortTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private NodeClientCore core;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private PeerManager peers;

  @Mock private NodeStats stats;
  @Mock private RequestTracker tracker;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private PersistentStatsPutter bandwidthStatsPutter;

  @Mock private BandwidthStatsContainer bandwidthStats;

  private LegacyStatisticsPort port;

  @BeforeEach
  void setUp() throws Exception {
    when(node.network().stats()).thenReturn(stats);
    when(node.network().peers()).thenReturn(peers);
    when(node.routing().tracker()).thenReturn(tracker);

    setRunningAverage(stats, "routingMissDistanceLocal");
    setRunningAverage(stats, "routingMissDistanceRemote");
    setRunningAverage(stats, "routingMissDistanceOverall");
    setRunningAverage(stats, "routingMissDistanceBulk");
    setRunningAverage(stats, "routingMissDistanceRT");
    setRunningAverage(stats, "backedOffPercent");

    port = new LegacyStatisticsPort(node, core);

    when(node.getConfig().get("node").getInt("outputBandwidthLimit")).thenReturn(10_000);
    when(node.getConfig().get("node").getInt("inputBandwidthLimit")).thenReturn(-1);
    when(node.getConfig().get("logger").getBoolean("enabled")).thenReturn(true);
    when(node.storage().getDataStoreStats()).thenReturn(Map.of());
    when(node.network().collector().getTotalIO()).thenReturn(new long[] {10_000L, 20_000L});
    when(node.getStartupTime()).thenReturn(System.currentTimeMillis() - 10_000L);
    when(node.isUsingWrapper()).thenReturn(true);
    when(node.getTotalPayloadSent()).thenReturn(1_000L);
    when(node.network().opennet()).thenReturn(null);
    when(node.network().usm().getUnclaimedFIFOMessageCounts()).thenReturn(Map.of());
    when(peers.getPeerNodeRoutingBackoffReasons(false)).thenReturn(new String[0]);
    when(peers.getPeerNodeRoutingBackoffReasons(true)).thenReturn(new String[0]);
    when(peers.statusBook().getPeerNodeStatuses(true))
        .thenReturn(new network.crypta.node.PeerNodeStatus[0]);
    when(core.getClientLayerPersister().getBandwidthStatsPutter()).thenReturn(bandwidthStatsPutter);
    when(bandwidthStatsPutter.getLatestBWData()).thenReturn(bandwidthStats);
    when(bandwidthStatsPutter.getLatestUptimeData().getTotalUptime()).thenReturn(60_000L);
    when(bandwidthStats.getTotalBytesIn()).thenReturn(40_000L);
    when(bandwidthStats.getTotalBytesOut()).thenReturn(30_000L);
    when(stats.getActiveThreadCount()).thenReturn(3);
    when(stats.getThreadLimit()).thenReturn(64);
    when(stats.getNodeIOStats()).thenReturn(new long[] {0L, 0L, 1_000L, 2_000L, 3_000L, 2_000L});
    when(stats.getIncomingRequestLocation()).thenReturn(new int[0]);
    when(stats.getOutgoingLocalRequestLocation()).thenReturn(new int[0]);
    when(stats.getOutgoingRequestLocation()).thenReturn(new int[0]);
    when(stats.getChkSuccessRatesByLocationPercentages(1000)).thenReturn(new int[0]);
    when(stats.getKnownLocations(-1)).thenReturn(new Object[] {new Double[0], new Long[0]});
    when(stats.getThreads()).thenReturn(new Thread[0]);
    when(stats.getActiveThreadsByPriority()).thenReturn(new int[0]);
    when(stats.getWaitingThreadsByPriority()).thenReturn(new int[0]);
    when(stats.getMandatoryBackoffStatistics(false)).thenReturn(new NodeStats.TimedStats[0]);
    when(stats.getMandatoryBackoffStatistics(true)).thenReturn(new NodeStats.TimedStats[0]);
    when(stats.getRoutingBackoffStatistics(false)).thenReturn(new NodeStats.TimedStats[0]);
    when(stats.getRoutingBackoffStatistics(true)).thenReturn(new NodeStats.TimedStats[0]);
    when(stats.getTransferBackoffStatistics(false)).thenReturn(new NodeStats.TimedStats[0]);
    when(stats.getTransferBackoffStatistics(true)).thenReturn(new NodeStats.TimedStats[0]);
    when(stats.enableNewLoadManagement(true)).thenReturn(false);
    when(stats.enableNewLoadManagement(false)).thenReturn(false);
  }

  @Test
  void overview_whenCalled_attemptsBandwidthRefresh() {
    port.overview(false);

    verify(bandwidthStatsPutter).updateData(node);
  }

  @Test
  void requesters_whenCalled_doesNotAttemptBandwidthRefresh() {
    port.requesters();

    verify(bandwidthStatsPutter, never()).updateData(node);
  }

  @Test
  void overview_whenCalled_includesDetachedPlaceholdersAndFlags() {
    StatisticsPageSnapshot snapshot = port.overview(false);

    assertTrue(snapshot.contentHtmlTemplate().contains("<!--CRYPTA_ALERT_SUMMARY-->"));
    assertTrue(snapshot.contentHtmlTemplate().contains("<!--CRYPTA_STAT_GATHERING_BOX-->"));
    assertTrue(snapshot.wrapperEnabled());
    assertTrue(snapshot.latestLogsEnabled());
  }

  @Test
  void overview_whenAdvancedEnabled_includesAdvancedOnlyContentAbsentFromBasicOverview() {
    try (MockedStatic<NodeStatsHtmlRenderer> renderer = mockStatic(NodeStatsHtmlRenderer.class)) {
      renderer
          .when(() -> NodeStatsHtmlRenderer.getRejectReasonsTable(same(stats), any(HTMLNode.class)))
          .thenReturn(false);
      renderer
          .when(
              () ->
                  NodeStatsHtmlRenderer.getLocalRejectReasonsTable(
                      same(stats), any(HTMLNode.class)))
          .thenReturn(false);

      StatisticsPageSnapshot basic = port.overview(false);
      StatisticsPageSnapshot advanced = port.overview(true);

      assertFalse(basic.contentHtmlTemplate().contains("Node status overview"));
      assertTrue(advanced.contentHtmlTemplate().contains("Node status overview"));
    }
  }

  @Test
  void requesters_whenActiveRequesterExists_rendersTableHeaderAndRequesterRow() {
    FreenetURI uri = mock(FreenetURI.class);
    when(uri.toString()).thenReturn("KSK@test-request");
    TestClientRequester requester =
        new TestClientRequester(
            (short) 3,
            new RequestClient() {
              @Override
              public boolean persistent() {
                return false;
              }

              @Override
              public boolean realTimeFlag() {
                return true;
              }

              @Override
              public String toString() {
                return "test-client";
              }
            },
            uri);

    StatisticsPageSnapshot snapshot = port.requesters();

    assertTrue(snapshot.contentHtmlTemplate().contains("RequestClient"));
    assertTrue(snapshot.contentHtmlTemplate().contains("test-client"));
    assertTrue(snapshot.contentHtmlTemplate().contains("KSK@test-request"));
    assertNotNull(requester);
  }

  @Test
  void overview_whenOptionalDataAbsent_returnsSnapshot() {
    when(node.network().opennet()).thenReturn(null);
    when(node.network().usm().getUnclaimedFIFOMessageCounts()).thenReturn(Map.of());
    when(bandwidthStatsPutter.getLatestBWData()).thenReturn(null);

    StatisticsPageSnapshot snapshot = assertDoesNotThrow(() -> port.overview(false));

    assertNotNull(snapshot);
    assertFalse(snapshot.contentHtmlTemplate().isBlank());
  }

  private void setRunningAverage(NodeStats target, String fieldName) throws Exception {
    RunningAverage runningAverage = mock(RunningAverage.class);
    when(runningAverage.currentValue()).thenReturn(0.0);
    Field field = NodeStats.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, runningAverage);
  }

  private static final class TestClientRequester extends ClientRequester {
    private final FreenetURI uri;

    private TestClientRequester(short priorityClass, RequestClient requestClient, FreenetURI uri) {
      super(priorityClass, requestClient);
      this.uri = uri;
    }

    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // No-op: this test stub is only used as passive requester data for rendering.
    }

    @Override
    public void cancel(ClientContext context) {
      // No-op: this test stub never participates in cancellation flows.
    }

    @Override
    public FreenetURI getURI() {
      return uri;
    }

    @Override
    public boolean isFinished() {
      return false;
    }

    @Override
    protected void innerNotifyClients(ClientContext context) {
      // No-op: no client callbacks are exercised by these rendering tests.
    }

    @Override
    protected void innerToNetwork(ClientContext context) {
      // No-op: this stub is not sent to the network in this test.
    }

    @Override
    protected ClientBaseCallback getCallback() {
      return null;
    }

    @Override
    public String toString() {
      return "TestClientRequester";
    }
  }
}
