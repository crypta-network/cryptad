package network.crypta.runtime.admin;

import java.util.List;
import java.util.Map;
import network.crypta.client.async.PersistentStatsPutter;
import network.crypta.clients.fcp.DownloadRequestStatus;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.RequestStatus;
import network.crypta.clients.fcp.UploadDirRequestStatus;
import network.crypta.clients.fcp.UploadFileRequestStatus;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeStats;
import network.crypta.node.PeerManager;
import network.crypta.node.RequestTracker;
import network.crypta.node.stats.DataStoreInstanceType;
import network.crypta.node.stats.DataStoreKeyType;
import network.crypta.node.stats.DataStoreStats;
import network.crypta.node.stats.DataStoreType;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.runtime.diagnostics.threads.NodeThreadInfo;
import network.crypta.runtime.diagnostics.threads.NodeThreadSnapshot;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.support.BandwidthStatsContainer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class LegacyDiagnosticPortTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private NodeClientCore core;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private PeerManager peers;

  @Mock private NodeStats stats;
  @Mock private RequestTracker tracker;
  @Mock private PersistentStatsPutter bandwidthStatsPutter;
  @Mock private BandwidthStatsContainer bandwidthStats;
  @Mock private FCPServer fcpServer;
  @Mock private SubConfig nodeConfig;

  private LegacyDiagnosticPort port;

  @BeforeEach
  void setUp() throws Exception {
    when(node.network().stats()).thenReturn(stats);
    when(node.network().peers()).thenReturn(peers);

    port = new LegacyDiagnosticPort(node, core);

    when(node.storage().getDataStoreStats()).thenReturn(Map.of());
    when(node.routing().tracker()).thenReturn(tracker);
    when(peers.statusBook().getPeerNodeStatuses(true))
        .thenReturn(new network.crypta.node.PeerNodeStatus[0]);
    when(node.network().opennet()).thenReturn(null);
    when(node.network().collector().getTotalIO()).thenReturn(new long[] {10_000L, 20_000L});
    when(node.getStartupTime()).thenReturn(System.currentTimeMillis() - 10_000L);
    when(node.getTotalPayloadSent()).thenReturn(1_000L);
    when(node.getConfig().get("node")).thenReturn(nodeConfig);
    lenient().when(nodeConfig.getInt("outputBandwidthLimit")).thenReturn(10_000);
    lenient().when(nodeConfig.getInt("inputBandwidthLimit")).thenReturn(-1);
    when(core.getClientLayerPersister().getBandwidthStatsPutter()).thenReturn(bandwidthStatsPutter);
    when(bandwidthStatsPutter.getLatestBWData()).thenReturn(bandwidthStats);
    lenient().when(bandwidthStats.getTotalBytesIn()).thenReturn(40_000L);
    lenient().when(bandwidthStats.getTotalBytesOut()).thenReturn(30_000L);
    when(core.getEndpoints().getFCPServer()).thenReturn(fcpServer);
    lenient().when(fcpServer.getGlobalRequests()).thenReturn(new RequestStatus[0]);
    when(stats.getActiveThreadCount()).thenReturn(3);
    when(stats.getThreadLimit()).thenReturn(64);
    lenient()
        .when(stats.getNodeIOStats())
        .thenReturn(new long[] {0L, 0L, 1_000L, 2_000L, 3_000L, 2_000L});
    when(node.isNodeDiagnosticsEnabled()).thenReturn(true);
    stubThreadSnapshot(defaultThreads());
  }

  @Test
  void snapshot_whenCalled_returnsStableSectionOrder() {
    DiagnosticReportSnapshot snapshot = port.snapshot();

    assertEquals(
        List.of(
            "Crypta Version:",
            "System Information:",
            "Store Size:",
            "Activity:",
            "Peer Statistics:",
            "Bandwidth:",
            "Queue:",
            "Threads (2):"),
        snapshot.sections().stream().map(DiagnosticSectionSnapshot::title).toList());
  }

  @Test
  void snapshot_whenCalled_attemptsBandwidthStatsRefreshBeforeBandwidthCollection() {
    var collector = node.network().collector();

    port.snapshot();

    InOrder inOrder = inOrder(bandwidthStatsPutter, collector);
    inOrder.verify(bandwidthStatsPutter).updateData(node);
    inOrder.verify(collector).getTotalIO();
  }

  @Test
  void snapshot_whenQueueContainsDownloadsAndUploads_countsExpectedRequestCategories()
      throws Exception {
    DownloadRequestStatus download = mock(DownloadRequestStatus.class);
    UploadFileRequestStatus uploadFile = mock(UploadFileRequestStatus.class);
    UploadDirRequestStatus uploadDir = mock(UploadDirRequestStatus.class);
    RequestStatus ignored = mock(RequestStatus.class);
    when(fcpServer.getGlobalRequests())
        .thenReturn(new RequestStatus[] {download, uploadFile, uploadDir, ignored});

    DiagnosticSectionSnapshot queueSection = findSection(port.snapshot(), "Queue:");

    assertEquals(
        List.of("Downloads Queued: 1 (1)", "Uploads Queued: 2 (2)", ""), queueSection.lines());
  }

  @Test
  void snapshot_whenStoreSuccessRatePresent_preservesLegacyBarePercentageLine() {
    DataStoreStats storeStats = mock(DataStoreStats.class);
    when(node.storage().getDataStoreStats())
        .thenReturn(
            Map.of(
                new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.STORE), storeStats));
    when(storeStats.getSessionAccessStats()).thenReturn(new FixedStoreAccessStats(1, 1));
    when(storeStats.keys()).thenReturn(5L);
    when(storeStats.capacity()).thenReturn(10L);
    when(storeStats.dataSize()).thenReturn(1_024L);
    when(storeStats.utilization()).thenReturn(0.5d);

    DiagnosticSectionSnapshot storeSection = findSection(port.snapshot(), "Store Size:");

    assertEquals("50.0000%", storeSection.lines().get(7));
  }

  @Test
  void snapshot_whenThreadDiagnosticsPresent_formatsSortedAndTruncated() {
    String longName = "ThreadName".repeat(15);
    String longGroup = "GroupNameLong";
    stubThreadSnapshot(
        List.of(
            new NodeThreadInfo(2L, 200L, 200_000_000L, "WorkerLow", 3, "GroupA", "RUNNABLE"),
            new NodeThreadInfo(1L, 100L, 600_000_000L, longName, 7, longGroup, "BLOCKED")));

    DiagnosticSectionSnapshot threadSection = findSection(port.snapshot(), "Threads (2):");
    String rendered = String.join("\n", threadSection.lines());

    assertTrue(rendered.contains("Thread ID"));
    assertTrue(rendered.contains(longName.substring(0, 90)));
    assertFalse(rendered.contains(longName));
    assertTrue(rendered.contains(longGroup.substring(0, 10)));
    assertTrue(rendered.indexOf("60.00") < rendered.indexOf("20.00"));
  }

  @Test
  void snapshot_whenOptionalDataAbsent_returnsBestEffortReport() {
    when(node.isNodeDiagnosticsEnabled()).thenReturn(false);
    when(bandwidthStatsPutter.getLatestBWData()).thenReturn(null);
    when(core.getEndpoints().getFCPServer()).thenReturn(null);

    DiagnosticReportSnapshot snapshot = assertDoesNotThrow(port::snapshot);

    assertEquals(
        List.of(
            "Crypta Version:",
            "System Information:",
            "Store Size:",
            "Activity:",
            "Peer Statistics:",
            "Bandwidth:",
            "Queue:"),
        snapshot.sections().stream().map(DiagnosticSectionSnapshot::title).toList());
    assertEquals(List.of("bandwidth error", ""), findSection(snapshot, "Bandwidth:").lines());
  }

  private void stubThreadSnapshot(List<NodeThreadInfo> threads) {
    when(node.services().nodeDiagnostics().getThreadDiagnostics().getThreadSnapshot())
        .thenReturn(new NodeThreadSnapshot(threads, 1_000));
  }

  private List<NodeThreadInfo> defaultThreads() {
    return List.of(
        new NodeThreadInfo(1L, 101L, 100_000_000L, "Worker-1", 5, "main", "RUNNABLE"),
        new NodeThreadInfo(2L, 202L, 50_000_000L, "Worker-2", 4, "main", "WAITING"));
  }

  private DiagnosticSectionSnapshot findSection(DiagnosticReportSnapshot snapshot, String title) {
    return snapshot.sections().stream()
        .filter(section -> section.title().equals(title))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Missing section: " + title));
  }

  private static final class FixedStoreAccessStats extends StoreAccessStats {
    private final long hits;
    private final long misses;

    private FixedStoreAccessStats(long hits, long misses) {
      this.hits = hits;
      this.misses = misses;
    }

    @Override
    public long hits() {
      return hits;
    }

    @Override
    public long misses() {
      return misses;
    }

    @Override
    public long falsePos() {
      return 0;
    }

    @Override
    public long writes() {
      return 0;
    }
  }
}
