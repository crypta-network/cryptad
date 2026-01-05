package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Method;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.node.Node;
import network.crypta.node.NodeStats;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNodeStatus;
import network.crypta.node.diagnostics.DefaultNodeDiagnostics;
import network.crypta.node.diagnostics.ThreadDiagnostics;
import network.crypta.node.diagnostics.threads.NodeThreadInfo;
import network.crypta.node.diagnostics.threads.NodeThreadSnapshot;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class DiagnosticToadletTest {

  private Node node;
  private NodeStats nodeStats;
  private PeerManager peerManager;
  private FCPServer fcpServer;
  private HighLevelSimpleClient client;

  @BeforeEach
  void setUp() {
    node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    nodeStats = mock(NodeStats.class);
    peerManager = mock(PeerManager.class);
    fcpServer = mock(FCPServer.class);
    client = mock(HighLevelSimpleClient.class);

    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.stats()).thenReturn(nodeStats);
    when(network.peers()).thenReturn(peerManager);
  }

  @Test
  void path_returnsDiagnosticUrl() {
    DiagnosticToadlet toadlet = new DiagnosticToadlet(node, fcpServer, client);

    assertEquals(DiagnosticToadlet.TOADLET_URL, toadlet.path());
  }

  @Test
  void handleMethodGET_whenAccessDenied_doesNotProceed() throws Exception {
    DiagnosticToadlet toadlet = spy(new DiagnosticToadlet(node, fcpServer, client));

    // Ignore constructor interactions when asserting later.
    reset(node, nodeStats, peerManager, fcpServer, client);

    ToadletContext ctx = mock(ToadletContext.class);
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    URI uri = new URI("http://localhost/diagnostic/");
    HTTPRequest request = mock(HTTPRequest.class);

    toadlet.handleMethodGET(uri, request, ctx);

    verify(ctx).checkFullAccess(toadlet);
    verify(toadlet, never()).writeTextReply(any(), anyInt(), anyString(), anyString());
    verifyNoMoreInteractions(ctx);
    verifyNoInteractions(node, nodeStats, peerManager, fcpServer, client);
  }

  @Test
  void getPeerStatusCount_whenRecordingAndStatusMatches_countsOnlyMatching() throws Exception {
    DiagnosticToadlet toadlet = new DiagnosticToadlet(node, fcpServer, client);

    PeerNodeStatus matching = mock(PeerNodeStatus.class);
    when(matching.recordStatus()).thenReturn(true);
    when(matching.getStatusValue()).thenReturn(5);

    PeerNodeStatus differentStatus = mock(PeerNodeStatus.class);
    when(differentStatus.recordStatus()).thenReturn(true);
    when(differentStatus.getStatusValue()).thenReturn(6);

    PeerNodeStatus notRecording = mock(PeerNodeStatus.class);
    when(notRecording.recordStatus()).thenReturn(false);

    PeerNodeStatus[] statuses = {matching, differentStatus, notRecording};

    int count = invokeGetPeerStatusCount(toadlet, statuses);

    assertEquals(1, count);
  }

  @Test
  void getCountSeedServers_whenMixed_countsOnlyFlagged() throws Exception {
    DiagnosticToadlet toadlet = new DiagnosticToadlet(node, fcpServer, client);

    PeerNodeStatus server = mock(PeerNodeStatus.class);
    when(server.isSeedServer()).thenReturn(true);

    PeerNodeStatus nonServer = mock(PeerNodeStatus.class);
    when(nonServer.isSeedServer()).thenReturn(false);

    int count = invokeGetCountSeedServers(toadlet, new PeerNodeStatus[] {server, nonServer});

    assertEquals(1, count);
  }

  @Test
  void getCountSeedClients_whenMixed_countsOnlyFlagged() throws Exception {
    DiagnosticToadlet toadlet = new DiagnosticToadlet(node, fcpServer, client);

    PeerNodeStatus clientStatus = mock(PeerNodeStatus.class);
    when(clientStatus.isSeedClient()).thenReturn(true);

    PeerNodeStatus nonClientStatus = mock(PeerNodeStatus.class);
    when(nonClientStatus.isSeedClient()).thenReturn(false);

    int count =
        invokeGetCountSeedClients(toadlet, new PeerNodeStatus[] {clientStatus, nonClientStatus});

    assertEquals(1, count);
  }

  @Test
  void threadsStats_whenSnapshotProvided_formatsSortedAndTruncated() throws Exception {
    Locale originalLocale = Locale.getDefault();
    Locale.setDefault(Locale.US);
    try {
      DefaultNodeDiagnostics nodeDiagnostics = mock(DefaultNodeDiagnostics.class);
      ThreadDiagnostics threadDiagnostics = mock(ThreadDiagnostics.class);
      network.crypta.node.subsystem.NodeServicesSubsystem services =
          org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
      when(node.services()).thenReturn(services);
      when(services.nodeDiagnostics()).thenReturn(nodeDiagnostics);
      when(nodeDiagnostics.getThreadDiagnostics()).thenReturn(threadDiagnostics);

      String longName = "ThreadName".repeat(15);
      String longGroup = "GroupNameLong";
      NodeThreadInfo lowUsage =
          new NodeThreadInfo(2L, 200L, 200_000_000L, "WorkerLow", 3, "GroupA", "RUNNABLE");
      NodeThreadInfo highUsage =
          new NodeThreadInfo(1L, 100L, 600_000_000L, longName, 7, longGroup, "BLOCKED");

      List<NodeThreadInfo> threads = Arrays.asList(lowUsage, highUsage);
      NodeThreadSnapshot snapshot = new NodeThreadSnapshot(threads, 1000);
      when(threadDiagnostics.getThreadSnapshot()).thenReturn(snapshot);

      DiagnosticToadlet toadlet = new DiagnosticToadlet(node, fcpServer, client);

      String output = invokeThreadsStats(toadlet).toString();

      assertTrue(output.contains("Threads (2):"));
      String truncatedName = longName.substring(0, 90);
      assertTrue(output.contains(truncatedName));
      assertFalse(output.contains(longName));

      String truncatedGroup = longGroup.substring(0, 10);
      assertTrue(output.contains(truncatedGroup));

      int highIndex = output.indexOf("60.00");
      int lowIndex = output.indexOf("20.00");
      assertTrue(highIndex > -1 && lowIndex > -1 && highIndex < lowIndex);
    } finally {
      Locale.setDefault(originalLocale);
    }
  }

  private int invokeGetPeerStatusCount(DiagnosticToadlet toadlet, PeerNodeStatus[] statuses)
      throws Exception {
    Method method =
        DiagnosticToadlet.class.getDeclaredMethod(
            "getPeerStatusCount", PeerNodeStatus[].class, int.class);
    method.setAccessible(true);
    return (int) method.invoke(toadlet, (Object) statuses, 5);
  }

  private int invokeGetCountSeedServers(DiagnosticToadlet toadlet, PeerNodeStatus[] statuses)
      throws Exception {
    Method method =
        DiagnosticToadlet.class.getDeclaredMethod("getCountSeedServers", PeerNodeStatus[].class);
    method.setAccessible(true);
    return (int) method.invoke(toadlet, (Object) statuses);
  }

  private int invokeGetCountSeedClients(DiagnosticToadlet toadlet, PeerNodeStatus[] statuses)
      throws Exception {
    Method method =
        DiagnosticToadlet.class.getDeclaredMethod("getCountSeedClients", PeerNodeStatus[].class);
    method.setAccessible(true);
    return (int) method.invoke(toadlet, (Object) statuses);
  }

  private StringBuilder invokeThreadsStats(DiagnosticToadlet toadlet) throws Exception {
    Method method = DiagnosticToadlet.class.getDeclaredMethod("threadsStats");
    method.setAccessible(true);
    return (StringBuilder) method.invoke(toadlet);
  }
}
