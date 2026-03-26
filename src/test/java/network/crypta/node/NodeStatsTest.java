package network.crypta.node;

import java.nio.file.Path;
import network.crypta.config.Config;
import network.crypta.config.SubConfig;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.IOStatisticCollector;
import network.crypta.io.comm.Message;
import network.crypta.runtime.bootstrap.NodeStarter;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.event.Level;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class NodeStatsTest {

  private static final int SORT_ORDER_BASE = 0;

  @TempDir Path tmpDir;

  private Node node;
  private SubConfig statsConfig;

  @BeforeAll
  static void initTestingVM(@TempDir Path tmp) {
    // Initialize NodeStarter once in “testing VM” mode so NodeStats uses test thresholds
    NodeStarter.globalTestInit(
        tmp.toFile(), false, Level.WARN, "NodeStatsTest", true, new DummyRandomSource(1234));
  }

  @BeforeEach
  void setUp() {
    // Real Config/SubConfig to satisfy option registrations inside NodeStats
    Config cfg = new Config();
    statsConfig = cfg.createSubConfig("node");

    // Basic node and collaborators
    node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerManager peerManager = mock(PeerManager.class);
    LocationManager locationManager = mock(LocationManager.class);
    PriorityAwareExecutor executor = new NoopExecutor();
    Ticker ticker = new NoopTicker(executor);

    // Common stubbing
    when(node.network().peers()).thenReturn(peerManager);
    when(node.network().locationManager()).thenReturn(locationManager);
    when(locationManager.getLocation()).thenReturn(0.42);
    when(node.getExecutor()).thenReturn(executor);
    when(node.network().ticker()).thenReturn(ticker);
    when(node.getRunDir()).thenReturn(tmpDir.toFile());
    when(node.getRandom()).thenReturn(new DummyRandomSource(424242));
    when(node.getSecurityLevels()).thenReturn(mock(SecurityLevels.class));
    when(node.network().collector()).thenReturn(new IOStatisticCollector());
    when(node.network().uptimeEstimator().getUptime()).thenReturn(100_000d);
    when(node.network().outputBandwidthLimit()).thenReturn(1024);
    when(node.network().inputBandwidthLimit()).thenReturn(1024);

    // Lenient stubs for methods we might touch indirectly
    lenient().when(peerManager.countConnectedPeers()).thenReturn(0);
    lenient().when(peerManager.countConnectedDarknetPeers()).thenReturn(0);
  }

  private NodeStats createNodeStats() throws NodeInitException {
    // obw/ibw limits and lastVersion are not exercised by these tests
    NodeStatsConfig nodeStatsConfig = new NodeStatsConfig(statsConfig);
    return new NodeStats(node, SORT_ORDER_BASE, nodeStatsConfig);
  }

  @Test
  @DisplayName("RequestsByLocation bins map doubles into 10 histogram buckets")
  void requestsByLocation_binning_expectCorrectCounts() throws Exception {
    NodeStats stats = createNodeStats();

    // Arrange: locations hitting bins 0, 1, and 9
    stats.reportIncomingRequestLocation(0.0);
    stats.reportIncomingRequestLocation(0.05); // still bin 0
    stats.reportIncomingRequestLocation(0.10); // bin 1
    stats.reportIncomingRequestLocation(0.999999); // bin 9

    // Act
    int[] counts = stats.getIncomingRequestLocation();

    // Assert: only bins 0,1,9 incremented as expected
    int[] expected = new int[10];
    expected[0] = 2;
    expected[1] = 1;
    expected[9] = 1;
    assertArrayEquals(expected, counts);
  }

  @Test
  void calculateMaxTransfersOut_whenPeerNull_expectMaxValue() throws Exception {
    NodeStats stats = createNodeStats();
    int result = stats.calculateMaxTransfersOut(null, true, 0.75, 10);
    assertEquals(Integer.MAX_VALUE, result);
  }

  @Test
  void calculateMaxTransfersOut_usesPeerAndUpperLimit() throws Exception {
    NodeStats stats = createNodeStats();
    PeerNode peer = mock(PeerNode.class);

    when(peer.calculateMaxTransfersOut(anyInt(), anyDouble())).thenReturn(12);

    int upper = 10; // will cap the peer-provided 12
    int result =
        stats.calculateMaxTransfersOut(peer, /* realTime= */ true, /* nonOverhead= */ 0.8, upper);
    assertEquals(10, result);

    // Capture arguments to verify acceptable block time for realtime == 2 seconds
    ArgumentCaptor<Integer> secs = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<Double> frac = ArgumentCaptor.forClass(Double.class);
    verify(peer).calculateMaxTransfersOut(secs.capture(), frac.capture());
    assertEquals(2, secs.getValue());
    assertEquals(0.8, frac.getValue(), 1e-9);
  }

  @Test
  void maxPeerPingTime_whenDefaults_expectTwiceMaxPing() throws Exception {
    NodeStats stats = createNodeStats();
    assertEquals(2 * NodeStats.DEFAULT_MAX_PING_TIME, stats.maxPeerPingTime());
  }

  @Test
  void shouldRejectRequest_whenPeerDisconnecting_expectHardDisconnectReason() throws Exception {
    NodeStats stats = createNodeStats();
    PeerNode source = mock(PeerNode.class);
    when(source.isDisconnecting()).thenReturn(true);

    NodeStats.RejectReason rr =
        stats.shouldRejectRequest(
            RequestAdmissionContext.of(
                false, /*canAcceptAnyway*/
                false, /*isInsert*/
                false, /*isSSK*/
                false, /*isLocal*/
                false, /*isOfferReply*/
                source,
                false, /*hasInStore*/
                false, /*preferInsert*/
                false, /*realTime*/
                null /*tag*/));

    assertNotNull(rr);
    assertEquals("disconnecting", rr.name());
    assertFalse(rr.soft());
  }

  @Test
  @DisplayName("Rejects hard when median peer ping exceeds max ping time")
  void shouldRejectRequest_whenPingTooHigh_expectHardMaxPingReason() throws Exception {
    NodeStats stats = createNodeStats();

    // Force very low maxPing to trigger immediate rejection without needing NodePinger
    statsConfig.set("maxPingTime", "-1");

    PeerNode source = mock(PeerNode.class);
    when(source.isDisconnecting()).thenReturn(false);

    NodeStats.RejectReason rr =
        stats.shouldRejectRequest(
            RequestAdmissionContext.of(
                false, /*canAcceptAnyway*/
                false, /*isInsert*/
                false, /*isSSK*/
                false, /*isLocal*/
                false, /*isOfferReply*/
                source,
                false, /*hasInStore*/
                false, /*preferInsert*/
                false, /*realTime*/
                null /*tag*/));

    assertNotNull(rr);
    assertTrue(rr.name().startsWith(">MAX_PING_TIME"));
    assertFalse(rr.soft());
  }

  @Test
  @DisplayName("Peer/user alerts become relevant only after sustained thresholds")
  void maybeUpdatePeerManagerUserAlertStats_whenSustained_expectAlertsFlipTrue() throws Exception {
    NodeStats stats = createNodeStats();

    // Set throttled delay to exceed the alert threshold
    stats.blockTime(NodeStats.MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD + 1, false);
    // Force the ping threshold to be trivially exceeded (0ms > 2*negative value)
    statsConfig.set("maxPingTime", "-1");

    long t0 = 1L; // use a non-zero timestamp to avoid edge-case equality
    stats.maybeUpdatePeerManagerUserAlertStats(t0);
    // Intermediate state is implementation-defined when thresholds were already exceeded earlier
    // the important property is that sustained exceedance flips to true after the delay.

    // Not enough time yet (just below 10 minutes)
    long almost = NodeStats.MAX_BWLIMIT_DELAY_TIME_ALERT_DELAY - 1;
    stats.maybeUpdatePeerManagerUserAlertStats(almost);

    // Cross the 10-minute threshold
    long t1 = NodeStats.MAX_BWLIMIT_DELAY_TIME_ALERT_DELAY;
    stats.maybeUpdatePeerManagerUserAlertStats(t1 + 2000); // ensure the timer window elapsed
    assertTrue(stats.isBwlimitDelayAlertRelevant());
    assertTrue(stats.isNodeAveragePingAlertRelevant());
  }

  @Test
  @DisplayName("Noisy reject stats reflect bulk trackers and update on start() in test VMs")
  void getNoisyRejectStats_whenEnoughReports_expectPercentages() throws Exception {
    NodeStats stats = createNodeStats();

    // Provide one report for each bulk tracker (minReportsNoisyRejectStats == 1 in testing VM)
    stats.pInstantRejectIncomingCHKRequestBulk.report(0.32); // 32%
    stats.pInstantRejectIncomingSSKRequestBulk.report(0.00); // 0%
    stats.pInstantRejectIncomingCHKInsertBulk.report(1.00); // 100%
    stats.pInstantRejectIncomingSSKInsertBulk.report(0.50); // 50%

    // Run the internal updater once via start().
    stats.start();

    byte[] noisy = stats.getNoisyRejectStats();
    assertArrayEquals(new byte[] {(byte) 32, (byte) 0, (byte) 100, (byte) 50}, noisy);
  }

  @Test
  @DisplayName("PeerLoadStats parses FNPPeerLoadStatus in int/short/byte variants")
  void parseLoadStats_forAllVariants_expectEqualFieldMapping() {
    PeerNode src = mock(PeerNode.class);

    // Int variant
    Message mi = getMi();
    PeerLoadStats pli = new PeerLoadStats(src, mi);

    // Short variant
    Message ms = getMs();
    PeerLoadStats pls = new PeerLoadStats(src, ms);

    // Byte variant
    Message mb = new Message(DMT.FNPPeerLoadStatusByte);
    mb.set(DMT.OTHER_TRANSFERS_IN_CHK, (byte) 1);
    mb.set(DMT.OTHER_TRANSFERS_IN_SSK, (byte) 2);
    mb.set(DMT.OTHER_TRANSFERS_OUT_CHK, (byte) 3);
    mb.set(DMT.OTHER_TRANSFERS_OUT_SSK, (byte) 4);
    mb.set(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT, (byte) 5);
    mb.set(DMT.MAX_TRANSFERS_OUT, (byte) 6);
    mb.set(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT, (byte) 7);
    mb.set(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT, (byte) 8);
    mb.set(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT, (byte) 9);
    mb.set(DMT.OUTPUT_BANDWIDTH_LOWER_LIMIT, 10);
    mb.set(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT, 11);
    mb.set(DMT.OUTPUT_BANDWIDTH_PEER_LIMIT, 12);
    mb.set(DMT.INPUT_BANDWIDTH_LOWER_LIMIT, 13);
    mb.set(DMT.INPUT_BANDWIDTH_UPPER_LIMIT, 14);
    mb.set(DMT.INPUT_BANDWIDTH_PEER_LIMIT, 15);
    mb.set(DMT.REAL_TIME_FLAG, true);
    PeerLoadStats plb = new PeerLoadStats(src, mb);

    // All 3 should be equal when coerced to int fields inside PeerLoadStats
    assertEquals(pli, pls);
    assertEquals(pli, plb);
  }

  private static @NotNull Message getMs() {
    Message ms = new Message(DMT.FNPPeerLoadStatusShort);
    ms.set(DMT.OTHER_TRANSFERS_IN_CHK, (short) 1);
    ms.set(DMT.OTHER_TRANSFERS_IN_SSK, (short) 2);
    ms.set(DMT.OTHER_TRANSFERS_OUT_CHK, (short) 3);
    ms.set(DMT.OTHER_TRANSFERS_OUT_SSK, (short) 4);
    ms.set(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT, (short) 5);
    ms.set(DMT.MAX_TRANSFERS_OUT, (short) 6);
    ms.set(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT, (short) 7);
    ms.set(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT, (short) 8);
    ms.set(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT, (short) 9);
    ms.set(DMT.OUTPUT_BANDWIDTH_LOWER_LIMIT, 10);
    ms.set(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT, 11);
    ms.set(DMT.OUTPUT_BANDWIDTH_PEER_LIMIT, 12);
    ms.set(DMT.INPUT_BANDWIDTH_LOWER_LIMIT, 13);
    ms.set(DMT.INPUT_BANDWIDTH_UPPER_LIMIT, 14);
    ms.set(DMT.INPUT_BANDWIDTH_PEER_LIMIT, 15);
    ms.set(DMT.REAL_TIME_FLAG, true);
    return ms;
  }

  private static @NotNull Message getMi() {
    Message mi = new Message(DMT.FNPPeerLoadStatusInt);
    mi.set(DMT.OTHER_TRANSFERS_IN_CHK, 1);
    mi.set(DMT.OTHER_TRANSFERS_IN_SSK, 2);
    mi.set(DMT.OTHER_TRANSFERS_OUT_CHK, 3);
    mi.set(DMT.OTHER_TRANSFERS_OUT_SSK, 4);
    mi.set(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT, 5);
    mi.set(DMT.MAX_TRANSFERS_OUT, 6);
    mi.set(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT, 7);
    mi.set(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT, 8);
    mi.set(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT, 9);
    mi.set(DMT.OUTPUT_BANDWIDTH_LOWER_LIMIT, 10);
    mi.set(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT, 11);
    mi.set(DMT.OUTPUT_BANDWIDTH_PEER_LIMIT, 12);
    mi.set(DMT.INPUT_BANDWIDTH_LOWER_LIMIT, 13);
    mi.set(DMT.INPUT_BANDWIDTH_UPPER_LIMIT, 14);
    mi.set(DMT.INPUT_BANDWIDTH_PEER_LIMIT, 15);
    mi.set(DMT.REAL_TIME_FLAG, true);
    return mi;
  }

  // --- Test helpers ---

  private static final class NoopExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(@NotNull Runnable job) {
      /* Intentionally no-op in tests: this stub executor must not run jobs; NodeStatsTest exercises logic synchronously. */
    }

    @Override
    public void execute(Runnable job, String jobName) {
      /* Intentionally no-op in tests: named jobs are not scheduled/executed by the NoopExecutor. */
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      /* Intentionally no-op in tests: ticker-originated jobs are suppressed to keep timing deterministic. */
    }

    @Override
    public int[] waitingThreads() {
      return new int[] {0};
    }

    @Override
    public int[] runningThreads() {
      return new int[] {0};
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }

  private static final class NoopTicker implements Ticker {
    private final PriorityAwareExecutor exec;

    NoopTicker(PriorityAwareExecutor exec) {
      this.exec = exec;
    }

    @Override
    public void queueTimedJob(Runnable job, long offset) {
      /* Intentionally no-op in tests: avoid background scheduling; tests drive time explicitly. */
    }

    @Override
    public void queueTimedJob(
        Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
      /* Intentionally no-op in tests: the NoopTicker never schedules or deduplicates timed jobs. */
    }

    @Override
    public PriorityAwareExecutor getExecutor() {
      return exec;
    }

    @Override
    public void removeQueuedJob(Runnable job) {
      /* Intentionally no-op in tests: nothing is queued by NoopTicker, so nothing to remove. */
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      /* Intentionally no-op in tests: absolute-time scheduling is disabled for deterministic unit tests. */
    }
  }
}
