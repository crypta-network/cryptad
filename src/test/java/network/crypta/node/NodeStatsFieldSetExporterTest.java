package network.crypta.node;

import java.lang.reflect.Field;
import network.crypta.io.comm.IOStatisticCollector;
import network.crypta.io.comm.MessageCore;
import network.crypta.store.CHKStore;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.TempBucketFactory;
import network.crypta.support.math.TimeDecayingRunningAverage;
import network.crypta.support.math.TrivialRunningAverage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class NodeStatsFieldSetExporterTest {

  @Test
  @SuppressWarnings("DataFlowIssue")
  void exportVolatileFieldSet_whenStatsNull_expectNullPointerException() {
    assertThrows(
        NullPointerException.class, () -> NodeStatsFieldSetExporter.exportVolatileFieldSet(null));
  }

  @Test
  void exportVolatileFieldSet_whenAveragesPresent_expectAverageSnapshotsWritten() {
    StatsFixture fixture = createStatsFixture();
    when(fixture.stats.getNodeAveragePingTime()).thenReturn(12.5);
    when(fixture.stats.getBwlimitDelayTime()).thenReturn(400.0);
    when(fixture.stats.getBwlimitDelayTimeRT()).thenReturn(40.0);
    when(fixture.stats.getBwlimitDelayTimeBulk()).thenReturn(60.0);
    when(fixture.stats.pRejectIncomingInstantly()).thenReturn(0.42);

    when(fixture.backedOffPercent.currentValue()).thenReturn(0.33);
    when(fixture.routingMissDistanceLocal.currentValue()).thenReturn(0.11);

    TrivialRunningAverage chkBulk = averageWithReports(150.0, 2);
    TrivialRunningAverage sskRt = averageWithReports(75.0, 1);
    setField(fixture.stats, "successfulLocalCHKFetchTimeAverageBulk", chkBulk);
    setField(fixture.stats, "successfulLocalSSKFetchTimeAverageRT", sskRt);

    SimpleFieldSet fs = NodeStatsFieldSetExporter.exportVolatileFieldSet(fixture.stats);

    assertEquals(12.5, fs.getDouble("averagePingTime", Double.NaN), 1e-9);
    assertEquals(400.0, fs.getDouble("bwlimitDelayTime", Double.NaN), 1e-9);
    assertEquals(40.0, fs.getDouble("bwlimitDelayTimeRT", Double.NaN), 1e-9);
    assertEquals(60.0, fs.getDouble("bwlimitDelayTimeBulk", Double.NaN), 1e-9);
    assertEquals(0.42, fs.getDouble("pInstantReject", Double.NaN), 1e-9);
    assertEquals(0.33, fs.getDouble("backedOffPercent", Double.NaN), 1e-9);
    assertEquals(0.11, fs.getDouble("routingMissDistanceLocal", Double.NaN), 1e-9);
    assertEquals(150.0, fs.getDouble("successfulLocalCHKFetchTimeBulk", Double.NaN), 1e-9);
    assertEquals(75.0, fs.getDouble("successfulLocalSSKFetchTimeRT", Double.NaN), 1e-9);
  }

  @Test
  void exportVolatileFieldSet_whenTotalsZeroAndDeltaZero_expectZeroRatesAndPercentMinusOne() {
    StatsFixture fixture = createStatsFixture();
    when(fixture.node.getStartupTime()).thenReturn(System.currentTimeMillis());
    when(fixture.collector.getTotalIO()).thenReturn(new long[] {0L, 0L});
    when(fixture.node.getTotalPayloadSent()).thenReturn(0L);
    when(fixture.stats.getNodeIOStats()).thenReturn(new long[] {10L, 20L, 30L, 40L, 50L, 30L});

    SimpleFieldSet fs = NodeStatsFieldSetExporter.exportVolatileFieldSet(fixture.stats);

    assertEquals(-1L, fs.getLong("totalPayloadOutputPercent", Long.MIN_VALUE));
    assertEquals(0L, fs.getLong("totalOutputRate", Long.MIN_VALUE));
    assertEquals(0L, fs.getLong("totalInputRate", Long.MIN_VALUE));
    assertEquals(0.0, fs.getDouble("recentOutputRate", Double.NaN), 1e-9);
    assertEquals(0.0, fs.getDouble("recentInputRate", Double.NaN), 1e-9);
    assertTrue(fs.getLong("uptimeSeconds", Long.MIN_VALUE) >= 1L);
  }

  @Test
  void exportVolatileFieldSet_whenMetricsPresent_expectDerivedSwapAndStoreValues() {
    StatsFixture fixture = createStatsFixture();
    when(fixture.node.getStartupTime()).thenReturn(System.currentTimeMillis() - 120_000L);
    when(fixture.collector.getTotalIO()).thenReturn(new long[] {1200L, 600L});
    when(fixture.node.getTotalPayloadSent()).thenReturn(300L);
    when(fixture.stats.getNodeIOStats())
        .thenReturn(new long[] {100L, 200L, 1000L, 400L, 800L, 2000L});

    when(fixture.node.network().swaps()).thenReturn(10);
    when(fixture.node.network().noSwaps()).thenReturn(5);
    when(fixture.node.network().numberOfRemotePeerLocationsSeenInSwaps()).thenReturn(30);
    when(fixture.node.network().locationChangeSession()).thenReturn(50.0);

    when(fixture.cache.keyCount()).thenReturn(2L);
    when(fixture.store.keyCount()).thenReturn(3L);
    when(fixture.node.getMaxTotalKeys()).thenReturn(10L);
    when(fixture.cache.hits()).thenReturn(10L);
    when(fixture.cache.misses()).thenReturn(5L);
    when(fixture.cache.writes()).thenReturn(7L);
    when(fixture.cache.getBloomFalsePositive()).thenReturn(1L);
    when(fixture.store.hits()).thenReturn(30L);
    when(fixture.store.misses()).thenReturn(10L);
    when(fixture.store.writes()).thenReturn(9L);
    when(fixture.store.getBloomFalsePositive()).thenReturn(2L);

    SimpleFieldSet fs = NodeStatsFieldSetExporter.exportVolatileFieldSet(fixture.stats);

    long uptimeSeconds = fs.getLong("uptimeSeconds", Long.MIN_VALUE);
    double minutes = uptimeSeconds / 60.0;

    assertEquals(300.0, fs.getDouble("recentOutputRate", Double.NaN), 1e-9);
    assertEquals(600.0, fs.getDouble("recentInputRate", Double.NaN), 1e-9);
    assertEquals(25L, fs.getLong("totalPayloadOutputPercent", Long.MIN_VALUE));
    assertEquals(2.0, fs.getDouble("avgConnectedPeersPerNode", Double.NaN), 1e-9);
    assertEquals(5.0, fs.getDouble("locationChangePerSwap", Double.NaN), 1e-9);
    assertEquals(2.0, fs.getDouble("swapsPerNoSwaps", Double.NaN), 1e-9);
    assertEquals(50.0, fs.getDouble("percentOverallKeysOfMax", Double.NaN), 1e-9);
    assertEquals(
        10.0 * 100.0 / 15.0, fs.getDouble("percentCachedStoreHitsOfAccesses", Double.NaN), 1e-9);
    assertEquals(75.0, fs.getDouble("percentStoreHitsOfAccesses", Double.NaN), 1e-9);
    assertEquals(50.0 / minutes, fs.getDouble("locationChangePerMinute", Double.NaN), 1e-9);
    assertEquals(10.0 / minutes, fs.getDouble("swapsPerMinute", Double.NaN), 1e-9);
    assertEquals(5.0 / minutes, fs.getDouble("noSwapsPerMinute", Double.NaN), 1e-9);
  }

  @Test
  void exportVolatileFieldSet_whenPeerStatusesAndBackoffReasons_expectCountsAndReasonFields() {
    StatsFixture fixture = createStatsFixture();

    PeerNodeStatus connected = mock(PeerNodeStatus.class);
    when(connected.getStatusValue()).thenReturn(PeerManager.PEER_NODE_STATUS_CONNECTED);
    when(connected.isSeedServer()).thenReturn(true);
    when(connected.isSeedClient()).thenReturn(false);

    PeerNodeStatus routingBackedOff = mock(PeerNodeStatus.class);
    when(routingBackedOff.getStatusValue())
        .thenReturn(PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF);
    when(routingBackedOff.isSeedServer()).thenReturn(false);
    when(routingBackedOff.isSeedClient()).thenReturn(true);

    PeerNodeStatus tooNew = mock(PeerNodeStatus.class);
    when(tooNew.getStatusValue()).thenReturn(PeerManager.PEER_NODE_STATUS_TOO_NEW);

    PeerNodeStatus disconnected = mock(PeerNodeStatus.class);
    when(disconnected.getStatusValue()).thenReturn(PeerManager.PEER_NODE_STATUS_DISCONNECTED);

    when(fixture.statusBook.getPeerNodeStatuses(true))
        .thenReturn(new PeerNodeStatus[] {connected, routingBackedOff, tooNew, disconnected});

    when(fixture.peers.getPeerNodeRoutingBackoffReasons(true))
        .thenReturn(new String[] {"rtReason"});
    when(fixture.peers.getPeerNodeRoutingBackoffReasonSize("rtReason", true)).thenReturn(2);
    when(fixture.peers.getPeerNodeRoutingBackoffReasons(false))
        .thenReturn(new String[] {"bulkReason"});
    when(fixture.peers.getPeerNodeRoutingBackoffReasonSize("bulkReason", false)).thenReturn(3);

    RequestTracker.WaitingForSlots waiting = new RequestTracker.WaitingForSlots();
    waiting.local = 4;
    waiting.remote = 6;
    when(fixture.tracker.countRequestsWaitingForSlots()).thenReturn(waiting);

    SimpleFieldSet fs = NodeStatsFieldSetExporter.exportVolatileFieldSet(fixture.stats);

    assertEquals(1L, fs.getLong("numberOfSeedServers", Long.MIN_VALUE));
    assertEquals(1L, fs.getLong("numberOfSeedClients", Long.MIN_VALUE));
    assertEquals(1L, fs.getLong("numberOfConnected", Long.MIN_VALUE));
    assertEquals(1L, fs.getLong("numberOfRoutingBackedOff", Long.MIN_VALUE));
    assertEquals(1L, fs.getLong("numberOfTooNew", Long.MIN_VALUE));
    assertEquals(1L, fs.getLong("numberOfDisconnected", Long.MIN_VALUE));
    assertEquals(2L, fs.getLong("numberOfSimpleConnected", Long.MIN_VALUE));
    assertEquals(2L, fs.getLong("numberOfNotConnected", Long.MIN_VALUE));
    assertEquals(2L, fs.getLong("numberWithRoutingBackoffReasonsRT.rtReason", Long.MIN_VALUE));
    assertEquals(3L, fs.getLong("numberWithRoutingBackoffReasonsBulk.bulkReason", Long.MIN_VALUE));
    assertEquals(4L, fs.getLong("RequestsWaitingSlotsLocal", Long.MIN_VALUE));
    assertEquals(6L, fs.getLong("RequestsWaitingSlotsRemote", Long.MIN_VALUE));
  }

  private static StatsFixture createStatsFixture() {
    StatsFixture fixture = new StatsFixture();
    fixture.stats = mock(NodeStats.class);
    fixture.node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    fixture.peers = mock(PeerManager.class);
    fixture.statusBook = mock(PeerStatusBook.class);
    fixture.tracker = mock(RequestTracker.class);
    fixture.usm = mock(MessageCore.class);
    fixture.clientCore = mock(NodeClientCore.class);
    fixture.tempBucketFactory = mock(TempBucketFactory.class);
    fixture.collector = mock(IOStatisticCollector.class);
    fixture.cache = mock(CHKStore.class);
    fixture.store = mock(CHKStore.class);

    fixture.backedOffPercent = mock(TimeDecayingRunningAverage.class);
    fixture.routingMissDistanceLocal = mock(TimeDecayingRunningAverage.class);
    fixture.routingMissDistanceRemote = mock(TimeDecayingRunningAverage.class);
    fixture.routingMissDistanceOverall = mock(TimeDecayingRunningAverage.class);
    fixture.routingMissDistanceBulk = mock(TimeDecayingRunningAverage.class);
    fixture.routingMissDistanceRT = mock(TimeDecayingRunningAverage.class);

    setField(fixture.stats, "node", fixture.node);
    setField(fixture.stats, "peers", fixture.peers);
    setField(fixture.stats, "backedOffPercent", fixture.backedOffPercent);
    setField(fixture.stats, "routingMissDistanceLocal", fixture.routingMissDistanceLocal);
    setField(fixture.stats, "routingMissDistanceRemote", fixture.routingMissDistanceRemote);
    setField(fixture.stats, "routingMissDistanceOverall", fixture.routingMissDistanceOverall);
    setField(fixture.stats, "routingMissDistanceBulk", fixture.routingMissDistanceBulk);
    setField(fixture.stats, "routingMissDistanceRT", fixture.routingMissDistanceRT);
    setField(fixture.stats, "successfulLocalCHKFetchTimeAverageBulk", averageWithReports(0.0, 1));
    setField(fixture.stats, "successfulLocalCHKFetchTimeAverageRT", averageWithReports(0.0, 1));
    setField(fixture.stats, "unsuccessfulLocalCHKFetchTimeAverageBulk", averageWithReports(0.0, 1));
    setField(fixture.stats, "unsuccessfulLocalCHKFetchTimeAverageRT", averageWithReports(0.0, 1));
    setField(fixture.stats, "successfulLocalSSKFetchTimeAverageBulk", averageWithReports(0.0, 1));
    setField(fixture.stats, "successfulLocalSSKFetchTimeAverageRT", averageWithReports(0.0, 1));
    setField(fixture.stats, "unsuccessfulLocalSSKFetchTimeAverageBulk", averageWithReports(0.0, 1));
    setField(fixture.stats, "unsuccessfulLocalSSKFetchTimeAverageRT", averageWithReports(0.0, 1));
    setField(fixture.stats, "globalFetchPSuccess", averageWithReports(0.0, 1));
    setField(fixture.stats, "chkLocalFetchPSuccess", averageWithReports(0.0, 1));
    setField(fixture.stats, "chkRemoteFetchPSuccess", averageWithReports(0.0, 1));
    setField(fixture.stats, "sskLocalFetchPSuccess", averageWithReports(0.0, 1));
    setField(fixture.stats, "sskRemoteFetchPSuccess", averageWithReports(0.0, 1));
    setField(fixture.stats, "blockTransferPSuccessRT", averageWithReports(0.0, 1));
    setField(fixture.stats, "blockTransferPSuccessBulk", averageWithReports(0.0, 1));
    setField(fixture.stats, "blockTransferFailTimeout", averageWithReports(0.0, 1));

    when(fixture.node.isUsingWrapper()).thenReturn(true);
    when(fixture.node.getStartupTime()).thenReturn(System.currentTimeMillis() - 1000L);
    when(fixture.node.network().usm()).thenReturn(fixture.usm);
    when(fixture.usm.getUnclaimedFIFOSize()).thenReturn(0);
    when(fixture.node.services().clientCore()).thenReturn(fixture.clientCore);
    when(fixture.clientCore.getTempBucketFactory()).thenReturn(fixture.tempBucketFactory);
    when(fixture.tempBucketFactory.getRamUsed()).thenReturn(0L);
    when(fixture.node.routing().tracker()).thenReturn(fixture.tracker);
    when(fixture.node.network().numArkFetchers()).thenReturn(0);
    when(fixture.node.network().stats()).thenReturn(fixture.stats);

    when(fixture.peers.statusBook()).thenReturn(fixture.statusBook);
    when(fixture.statusBook.getPeerNodeStatuses(true)).thenReturn(new PeerNodeStatus[0]);
    when(fixture.peers.getPeerNodeRoutingBackoffReasons(true)).thenReturn(new String[0]);
    when(fixture.peers.getPeerNodeRoutingBackoffReasons(false)).thenReturn(new String[0]);

    when(fixture.stats.getNodeAveragePingTime()).thenReturn(0.0);
    when(fixture.stats.getBwlimitDelayTime()).thenReturn(0.0);
    when(fixture.stats.getBwlimitDelayTimeRT()).thenReturn(0.0);
    when(fixture.stats.getBwlimitDelayTimeBulk()).thenReturn(0.0);
    when(fixture.stats.getOpennetSizeEstimate(anyLong())).thenReturn(0);
    when(fixture.stats.getDarknetSizeEstimate(anyLong())).thenReturn(0);
    when(fixture.stats.pRejectIncomingInstantly()).thenReturn(0.0);
    when(fixture.stats.getNlmDelaySnapshot()).thenReturn(new double[] {0.0, 0.0, 0.0, 0.0});
    when(fixture.stats.getSlotTimeoutSnapshot()).thenReturn(new long[] {0L, 0L, 0L, 0L});
    when(fixture.stats.getNodeIOStats()).thenReturn(new long[] {0L, 0L, 0L, 0L, 0L, 0L});
    when(fixture.stats.getNotificationOnlyPacketsSentBytes()).thenReturn(0L);
    when(fixture.stats.getResendBytesSent()).thenReturn(0L);
    when(fixture.stats.getUOMBytesSent()).thenReturn(0L);
    when(fixture.stats.getAnnounceBytesPayloadSent()).thenReturn(0L);
    when(fixture.stats.getAnnounceBytesSent()).thenReturn(0L);
    when(fixture.stats.getActiveThreadCount()).thenReturn(0);
    when(fixture.stats.getBandwidthLiabilityUsage()).thenReturn(0.0);

    when(fixture.collector.getTotalIO()).thenReturn(new long[] {0L, 0L});
    when(fixture.node.network().collector()).thenReturn(fixture.collector);
    when(fixture.node.getTotalPayloadSent()).thenReturn(0L);

    when(fixture.node.network().swaps()).thenReturn(0);
    when(fixture.node.network().noSwaps()).thenReturn(0);
    when(fixture.node.network().numberOfRemotePeerLocationsSeenInSwaps()).thenReturn(0);
    when(fixture.node.network().startedSwaps()).thenReturn(0);
    when(fixture.node.network().swapsRejectedAlreadyLocked()).thenReturn(0);
    when(fixture.node.network().swapsRejectedNowhereToGo()).thenReturn(0);
    when(fixture.node.network().swapsRejectedRateLimit()).thenReturn(0);
    when(fixture.node.network().swapsRejectedRecognizedID()).thenReturn(0);
    when(fixture.node.network().locationChangeSession()).thenReturn(0.0);

    when(fixture.node.storage().getChkDatacache()).thenReturn(fixture.cache);
    when(fixture.node.storage().getChkDatastore()).thenReturn(fixture.store);
    when(fixture.node.getMaxTotalKeys()).thenReturn(10L);
    when(fixture.cache.keyCount()).thenReturn(0L);
    when(fixture.store.keyCount()).thenReturn(0L);
    when(fixture.cache.hits()).thenReturn(1L);
    when(fixture.cache.misses()).thenReturn(1L);
    when(fixture.cache.writes()).thenReturn(0L);
    when(fixture.cache.getBloomFalsePositive()).thenReturn(0L);
    when(fixture.store.hits()).thenReturn(1L);
    when(fixture.store.misses()).thenReturn(1L);
    when(fixture.store.writes()).thenReturn(0L);
    when(fixture.store.getBloomFalsePositive()).thenReturn(0L);

    when(fixture.tracker.getNumLocalCHKInserts()).thenReturn(0);
    when(fixture.tracker.getNumRemoteCHKInserts()).thenReturn(0);
    when(fixture.tracker.getNumLocalSSKInserts()).thenReturn(0);
    when(fixture.tracker.getNumRemoteSSKInserts()).thenReturn(0);
    when(fixture.tracker.getNumLocalCHKRequests()).thenReturn(0);
    when(fixture.tracker.getNumRemoteCHKRequests()).thenReturn(0);
    when(fixture.tracker.getNumLocalSSKRequests()).thenReturn(0);
    when(fixture.tracker.getNumRemoteSSKRequests()).thenReturn(0);
    when(fixture.tracker.getNumTransferringRequestSenders()).thenReturn(0);
    when(fixture.tracker.getNumTransferringRequestHandlers()).thenReturn(0);
    when(fixture.tracker.getNumCHKOfferReplies()).thenReturn(0);
    when(fixture.tracker.getNumSSKOfferReplies()).thenReturn(0);

    RequestTracker.WaitingForSlots waiting = new RequestTracker.WaitingForSlots();
    waiting.local = 0;
    waiting.remote = 0;
    when(fixture.tracker.countRequestsWaitingForSlots()).thenReturn(waiting);
    return fixture;
  }

  private static TrivialRunningAverage averageWithReports(double value, int reports) {
    TrivialRunningAverage average = new TrivialRunningAverage();
    for (int i = 0; i < reports; i++) {
      average.report(value);
    }
    return average;
  }

  @SuppressWarnings("java:S3011")
  private static void setField(NodeStats stats, String fieldName, Object value) {
    try {
      Field field = NodeStats.class.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(stats, value);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Failed to set field " + fieldName, e);
    }
  }

  private static final class StatsFixture {
    private NodeStats stats;
    private Node node;
    private PeerManager peers;
    private PeerStatusBook statusBook;
    private RequestTracker tracker;
    private MessageCore usm;
    private NodeClientCore clientCore;
    private TempBucketFactory tempBucketFactory;
    private IOStatisticCollector collector;
    private CHKStore cache;
    private CHKStore store;
    private TimeDecayingRunningAverage backedOffPercent;
    private TimeDecayingRunningAverage routingMissDistanceLocal;
    private TimeDecayingRunningAverage routingMissDistanceRemote;
    private TimeDecayingRunningAverage routingMissDistanceOverall;
    private TimeDecayingRunningAverage routingMissDistanceBulk;
    private TimeDecayingRunningAverage routingMissDistanceRT;
  }
}
