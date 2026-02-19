package network.crypta.node;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.async.BaseClientPutter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.io.comm.Peer;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class NodeARKInserterTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeCrypto crypto;
  @Mock private NodeIPPortDetector detector;
  @Mock private PeerManager peerManager;
  @Mock private PeerMessenger peerMessenger;
  @Mock private NodeClientCore core;
  @Mock private HighLevelSimpleClient hlsc;
  @Mock private ClientContext clientContext;

  @BeforeEach
  void setUp() throws Exception {
    // Synchronous executor to make update() deterministic
    PriorityAwareExecutor inlineExecutor =
        new PriorityAwareExecutor() {
          @Override
          public void execute(@NonNull Runnable job) {
            job.run();
          }

          @Override
          public void execute(Runnable job, String jobName) {
            job.run();
          }

          @Override
          public void execute(Runnable job, String jobName, boolean fromTicker) {
            job.run();
          }

          @Override
          public int[] waitingThreads() {
            return new int[0];
          }

          @Override
          public int[] runningThreads() {
            return new int[0];
          }

          @Override
          public int getWaitingThreadsCount() {
            return 0;
          }
        };

    when(node.getExecutor()).thenReturn(inlineExecutor);
    org.mockito.Mockito.lenient().when(node.network().peers()).thenReturn(peerManager);
    org.mockito.Mockito.lenient().when(peerManager.messenger()).thenReturn(peerMessenger);
    org.mockito.Mockito.lenient().when(node.services().clientCore()).thenReturn(core);
    org.mockito.Mockito.lenient().when(core.getClientContext()).thenReturn(clientContext);

    // Default: provide an InsertContext so ClientPutter constructor receives a non-null ctx
    InsertContext ctx =
        new InsertContext(
            InsertContextOptions.builder()
                .retryLimits(1, 1)
                .splitfileSegmentLimits(1, 1)
                .clientOptions(new SimpleEventProducer(), true, false, false)
                .compressorDescriptor(null)
                .redundancy(0, 0)
                .compatibility(InsertContext.CompatibilityMode.COMPAT_DEFAULT)
                .build());
    org.mockito.Mockito.lenient().when(core.makeClient((short) 0, true, false)).thenReturn(hlsc);
    org.mockito.Mockito.lenient().when(hlsc.getInsertContext(true)).thenReturn(ctx);

    // Do nothing when clientContext.start(...) is called; we only assert it was invoked.
    org.mockito.Mockito.lenient()
        .doAnswer(invocation -> null)
        .when(clientContext)
        .start(any(ClientPutter.class));

    // Default: crypto is darknet unless overridden
    org.mockito.Mockito.lenient().when(crypto.isOpennet()).thenReturn(false);
  }

  private static SimpleFieldSet fsWithUdp(String... udp) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putOverwrite("physical.udp", udp);
    return fs;
  }

  private NodeARKInserter newInserter(boolean enableARKs) {
    return new NodeARKInserter(node, crypto, detector, enableARKs);
  }

  @Test
  void start_whenDisabled_noAction() throws Exception {
    // Arrange
    NodeARKInserter inserter = newInserter(false);

    // Act
    inserter.start();

    // Assert
    verify(detector, never()).detectPrimaryPeers();
    verify(node.network(), never()).peers();
    verify(core, never()).makeClient(any(short.class), any(boolean.class), any(boolean.class));
    verify(clientContext, never()).start(any(ClientPutter.class));
  }

  @Test
  void update_whenNoIp_noBroadcastOrInsert() throws Exception {
    // Arrange
    NodeARKInserter inserter = newInserter(true);
    when(detector.detectPrimaryPeers()).thenReturn(null);

    // Act
    inserter.update(); // runs inline via inlineExecutor

    // Assert
    verify(node.network(), never()).peers();
    verify(clientContext, never()).start(any(ClientPutter.class));
  }

  @Test
  void start_whenEnabled_andConnected_broadcastsAndStartsInserter() throws Exception {
    // Arrange
    NodeARKInserter inserter = newInserter(true);
    when(detector.detectPrimaryPeers()).thenReturn(new Peer[] {mock(Peer.class)});
    when(crypto.exportPublicFieldSet(false, false, true)).thenReturn(fsWithUdp("127.0.0.1:12345"));
    when(node.noConnectedPeers()).thenReturn(false);

    InsertableClientSSK ssk = mock(InsertableClientSSK.class);
    when(crypto.getMyARK()).thenReturn(ssk);
    when(crypto.getMyARKNumber()).thenReturn(42L);
    when(ssk.getInsertURI()).thenReturn(new FreenetURI("SSK", "ark"));

    // Act
    inserter.start(); // innerUpdate() runs synchronously

    // Assert
    // Broadcast differential noderef with physical.udp
    ArgumentCaptor<SimpleFieldSet> sfsCaptor = ArgumentCaptor.forClass(SimpleFieldSet.class);
    verify(peerMessenger).locallyBroadcastDiffNodeRef(sfsCaptor.capture(), eq(true), eq(false));
    assertEquals("127.0.0.1:12345", sfsCaptor.getValue().get("physical.udp"));

    // Insert started
    ArgumentCaptor<ClientPutter> putterCaptor = ArgumentCaptor.forClass(ClientPutter.class);
    verify(clientContext, times(1)).start(putterCaptor.capture());
    assertInstanceOf(ClientPutter.class, putterCaptor.getValue());
  }

  @Test
  void onConnectedPeer_whenQueuedDueToNoPeers_startsInserter() throws Exception {
    // Arrange
    NodeARKInserter inserter = newInserter(true);
    when(detector.detectPrimaryPeers()).thenReturn(new Peer[] {mock(Peer.class)});
    when(crypto.exportPublicFieldSet(false, false, true)).thenReturn(fsWithUdp("127.0.0.1:12345"));
    // First call: no connected peers -> queue shouldInsert; Second call: peers present
    when(node.noConnectedPeers()).thenReturn(true);

    InsertableClientSSK ssk = mock(InsertableClientSSK.class);
    when(crypto.getMyARK()).thenReturn(ssk);
    when(crypto.getMyARKNumber()).thenReturn(1L);
    when(ssk.getInsertURI()).thenReturn(new FreenetURI("SSK", "ark"));

    // Start queues the insert because there are no connected peers
    inserter.start();
    verify(clientContext, never()).start(any(ClientPutter.class));

    // Peers connected now
    when(node.noConnectedPeers()).thenReturn(false);

    // Act
    inserter.onConnectedPeer();

    // Assert
    verify(clientContext, times(1)).start(any(ClientPutter.class));
  }

  @Test
  void onGeneratedURI_whenHigherEdition_darknet_updatesAndBroadcasts() {
    // Arrange
    NodeARKInserter inserter = newInserter(true);
    when(crypto.isOpennet()).thenReturn(false);
    when(crypto.getMyARKNumber()).thenReturn(5L, 5L, 7L);
    when(node.network().peers()).thenReturn(peerManager);

    FreenetURI uri = new FreenetURI(new byte[] {1}, new byte[32], null, "site", 7L);

    // Act
    inserter.onGeneratedURI(uri, mock(BaseClientPutter.class));

    // Assert
    verify(crypto).setMyARKNumber(7L);
    verify(node).writeNodeFile();
    verify(node, never()).writeOpennetFile();

    ArgumentCaptor<SimpleFieldSet> sfsCaptor = ArgumentCaptor.forClass(SimpleFieldSet.class);
    verify(peerMessenger).locallyBroadcastDiffNodeRef(sfsCaptor.capture(), eq(true), eq(false));
    assertEquals(7L, Long.parseLong(sfsCaptor.getValue().get("ark.number")));
  }

  @Test
  void onGeneratedURI_whenHigherEdition_opennet_updatesAndBroadcasts() {
    // Arrange
    NodeARKInserter inserter = newInserter(true);
    when(crypto.isOpennet()).thenReturn(true);
    when(crypto.getMyARKNumber()).thenReturn(2L, 2L, 3L);

    FreenetURI uri = new FreenetURI(new byte[] {1}, new byte[32], null, "site", 3L);

    // Act
    inserter.onGeneratedURI(uri, mock(BaseClientPutter.class));

    // Assert
    verify(crypto).setMyARKNumber(3L);
    verify(node).writeOpennetFile();
    verify(node, never()).writeNodeFile();

    ArgumentCaptor<SimpleFieldSet> sfsCaptor = ArgumentCaptor.forClass(SimpleFieldSet.class);
    verify(peerMessenger).locallyBroadcastDiffNodeRef(sfsCaptor.capture(), eq(false), eq(true));
    assertEquals(3L, Long.parseLong(sfsCaptor.getValue().get("ark.number")));
  }

  @Test
  void onGeneratedURI_whenLowerEdition_noUpdateNoBroadcast() {
    // Arrange
    NodeARKInserter inserter = newInserter(true);
    when(crypto.getMyARKNumber()).thenReturn(10L);

    FreenetURI uri = new FreenetURI(new byte[] {1}, new byte[32], null, "site", 8L);

    // Act
    inserter.onGeneratedURI(uri, mock(BaseClientPutter.class));

    // Assert
    verify(crypto, never()).setMyARKNumber(any(Long.class));
    verify(node, never()).writeNodeFile();
    verify(node, never()).writeOpennetFile();
    verifyNoInteractions(peerMessenger);
  }

  @Test
  void onGeneratedMetadata_freesBucket() {
    // Arrange
    NodeARKInserter inserter = newInserter(true);
    Bucket bucket = mock(Bucket.class);

    // Act
    inserter.onGeneratedMetadata(bucket, mock(BaseClientPutter.class));

    // Assert
    verify(bucket, times(1)).free();
  }

  @Test
  void persistent_and_realTimeFlag_areFalse() {
    // Arrange
    NodeARKInserter inserter = newInserter(true);

    // Act & Assert
    assertFalse(inserter.persistent());
    assertFalse(inserter.realTimeFlag());
  }

  @Test
  void onFailure_restartsInserter_withoutSleep_whenInterrupted() throws Exception {
    // Arrange
    NodeARKInserter inserter = newInserter(true);
    when(detector.detectPrimaryPeers()).thenReturn(new Peer[] {mock(Peer.class)});
    when(crypto.exportPublicFieldSet(false, false, true)).thenReturn(fsWithUdp("127.0.0.1:9999"));

    InsertableClientSSK ssk = mock(InsertableClientSSK.class);
    when(crypto.getMyARK()).thenReturn(ssk);
    when(crypto.getMyARKNumber()).thenReturn(1L);
    when(ssk.getInsertURI()).thenReturn(new FreenetURI("SSK", "ark"));

    // start() sets canStart = true, but we avoid initial insert by returning no IPs or no peers
    // here we keep noConnectedPeers() true so innerUpdate queues and exits quickly
    when(node.noConnectedPeers()).thenReturn(true);
    inserter.start();

    // Now allow insertion on retry
    when(node.noConnectedPeers()).thenReturn(false);

    // Make Thread.sleep(5000) return immediately by interrupting the test thread.
    // Ensure we restore the thread's interrupt status after the assertion so later tests
    // don't inherit an interrupted worker thread.
    boolean wasInterrupted = Thread.currentThread().isInterrupted();
    Thread.currentThread().interrupt();
    try {
      // Act
      inserter.onFailure(
          new InsertException(InsertExceptionMode.CANCELLED, "x", null),
          mock(BaseClientPutter.class));
    } finally {
      // Clear the interrupt we set; re‑assert if it was already set before this test.
      // Capture and use the return value to satisfy static analysis (and document behavior).
      boolean clearedNow = Thread.interrupted();
      if (wasInterrupted) Thread.currentThread().interrupt();
      assertTrue(clearedNow || wasInterrupted);
    }

    // Assert: a new inserter was started
    verify(clientContext, times(1)).start(any(ClientPutter.class));
  }
}
