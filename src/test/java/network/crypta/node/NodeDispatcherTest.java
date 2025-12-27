package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.concurrent.atomic.AtomicReference;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.Peer;
import network.crypta.keys.NodeCHK;
import network.crypta.node.NodeDispatcher.NodeDispatcherCallback;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.node.updater.UpdateOverMandatoryManager;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.ShortBuffer;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeDispatcherTest {

  @Mock Node node;
  @Mock RequestTracker tracker;
  @Mock NodeStats stats;
  @Mock Ticker ticker;
  @Mock PriorityAwareExecutor executor;

  private NodeDispatcher dispatcher;

  @BeforeEach
  void setUp() {
    // Common node wiring required by the constructor
    when(node.getTracker()).thenReturn(tracker);
    when(node.getNodeStats()).thenReturn(stats);
    when(node.getTicker()).thenReturn(ticker);
    // The constructor schedules a periodic task; execute nothing in tests.
    doAnswer(inv -> null).when(ticker).queueTimedJob(any(Runnable.class), anyLong());
    // Minimal config tree so Probe(node) can register options under the "node" SubConfig
    network.crypta.config.PersistentConfig cfg = new network.crypta.config.PersistentConfig(null);
    cfg.createSubConfig("node");
    when(node.getConfig()).thenReturn(cfg);
    // Provide a minimal RandomSource so Probe's identifier setter can call nextLong()
    network.crypta.crypt.RandomSource rnd =
        new network.crypta.crypt.RandomSource() {
          @Override
          public int acceptEntropy(
              network.crypta.crypt.EntropySource source, long data, int entropyGuess) {
            return 0;
          }

          @Override
          public int acceptTimerEntropy(network.crypta.crypt.EntropySource timer) {
            return 0;
          }

          @Override
          public int acceptTimerEntropy(
              network.crypta.crypt.EntropySource fnpTimingSource, double bias) {
            return 0;
          }

          @Override
          public int acceptEntropyBytes(
              network.crypta.crypt.EntropySource myPacketDataSource,
              byte[] buf,
              int offset,
              int length,
              double bias) {
            return 0;
          }

          @Override
          public void close() {
            // Test stub: RandomSource has no background collectors or OS handles here.
            // Intentionally a no-op to satisfy static analysis of empty methods.
          }
        };
    when(node.getRandom()).thenReturn(rnd);
    dispatcher = new NodeDispatcher(node);
  }

  // ---- helpers ----

  private static Message withSource(Message m, PeerNode source) {
    byte[] encoded = m.encodeToPacket();
    // Decode to attach a source peer context to the message instance used by the dispatcher
    return Message.decodeMessageLax(encoded, source, 0);
  }

  private static PeerNode peerMock() {
    PeerNode pn = mock(PeerNode.class);
    org.mockito.Mockito.lenient().when(pn.getPeer()).thenReturn(mock(Peer.class));
    org.mockito.Mockito.lenient().when(pn.isConnected()).thenReturn(true);
    org.mockito.Mockito.lenient().when(pn.isRoutable()).thenReturn(true);
    org.mockito.Mockito.lenient().when(pn.isRealConnection()).thenReturn(true);
    java.lang.ref.WeakReference<PeerNode> ref = new java.lang.ref.WeakReference<>(pn);
    org.mockito.Mockito.lenient().when(pn.getWeakRef()).thenReturn(ref);
    return pn;
  }

  // ---- peersUIDsToString ----

  @Test
  @DisplayName("peersUIDsToString when lengths equal -> pairs with pipe")
  void peersUIDsToString_whenLengthsEqual_expectPairsDelimited() {
    long[] uids = {1L, 2L};
    double[] locs = {0.1, 0.2};
    String s = NodeDispatcher.peersUIDsToString(uids, locs);
    assertEquals("0.1=1|0.2=2", s);
  }

  @Test
  @DisplayName("peersUIDsToString when extra UIDs -> U sections appended")
  void peersUIDsToString_whenExtraUIDs_expectUSections() {
    long[] uids = {10L, 20L, 30L};
    double[] locs = {0.5};
    String s = NodeDispatcher.peersUIDsToString(uids, locs);
    assertEquals("0.5=10|U:20|U:30", s);
  }

  @Test
  @DisplayName("peersUIDsToString when extra locs -> L sections appended")
  void peersUIDsToString_whenExtraLocs_expectLSections() {
    long[] uids = {10L};
    double[] locs = {0.5, 0.6};
    String s = NodeDispatcher.peersUIDsToString(uids, locs);
    assertEquals("0.5=10|L:0.6", s);
  }

  // ---- basic message handling branches ----

  @Captor ArgumentCaptor<Message> msgCaptor;
  @Captor ArgumentCaptor<ByteCounter> ctrCaptor;

  @Test
  void handleMessage_whenPing_expectPongSentAndTrue() throws NotConnectedException {
    PeerNode src = peerMock();
    Message ping = withSource(DMT.createFNPPing(1234), src);
    org.junit.jupiter.api.Assertions.assertNotNull(ping.getSource());

    boolean handled = dispatcher.handleMessage(ping);

    assertTrue(handled);
    verify(src).sendAsync(msgCaptor.capture(), eq(null), ctrCaptor.capture());

    Message reply = msgCaptor.getValue();
    assertEquals(DMT.FNPPong, reply.getSpec());
    assertEquals(1234, reply.getInt(DMT.PING_SEQNO));

    // Prove the ByteCounter is wired to NodeStats.pingCounterSent by invoking it.
    ByteCounter ctr = ctrCaptor.getValue();
    ctr.sentBytes(42);
    verify(stats, times(1)).pingCounterSent(42);
  }

  @Test
  void handleMessage_whenDetectedIP_expectPeerUpdatedAndRedetect() {
    PeerNode src = peerMock();
    Peer detected = new Peer(java.net.InetAddress.getLoopbackAddress(), 12345);
    Message m = withSource(DMT.createFNPDetectedIPAddress(detected), src);
    org.junit.jupiter.api.Assertions.assertNotNull(m.getSource());

    NodeIPDetector ipDetector = mock(NodeIPDetector.class);
    when(node.getIpDetector()).thenReturn(ipDetector);

    boolean handled = dispatcher.handleMessage(m);

    assertTrue(handled);
    verify(src).setRemoteDetectedPeer(detected);
    verify(ipDetector).redetectAddress();
  }

  @Test
  void handleMessage_whenTime_expectDeltaSet() {
    PeerNode src = peerMock();
    long future = System.currentTimeMillis() + 500; // ~0.5s ahead
    Message m = withSource(DMT.createFNPTime(future), src);

    boolean handled = dispatcher.handleMessage(m);

    assertTrue(handled);
    ArgumentCaptor<Long> deltaCap = ArgumentCaptor.forClass(Long.class);
    verify(src).setTimeDelta(deltaCap.capture());
    long delta = deltaCap.getValue();
    // Allow generous tolerance for CI jitter
    assertTrue(Math.abs(delta - 500) <= 250, "delta within 250ms of expected");
  }

  @Test
  void handleMessage_whenUptime_expectSetUptime() {
    PeerNode src = peerMock();
    byte uptime = 77;
    Message m = withSource(DMT.createFNPUptime(uptime), src);

    assertTrue(dispatcher.handleMessage(m));
    verify(src).setUptime(uptime);
  }

  @Test
  void handleMessage_whenVisibilityFromDarknetPeer_expectHandled() {
    DarknetPeerNode src = mock(DarknetPeerNode.class);
    org.mockito.Mockito.lenient().when(src.getPeer()).thenReturn(mock(Peer.class));
    org.mockito.Mockito.lenient().when(src.isConnected()).thenReturn(true);
    org.mockito.Mockito.lenient().when(src.isRoutable()).thenReturn(true);
    org.mockito.Mockito.lenient().when(src.isRealConnection()).thenReturn(true);
    java.lang.ref.WeakReference<PeerNode> ref = new java.lang.ref.WeakReference<>(src);
    org.mockito.Mockito.lenient().when(src.getWeakRef()).thenReturn(ref);

    Message m = withSource(DMT.createFNPVisibility((short) 1), src);
    assertTrue(dispatcher.handleMessage(m));
    verify(src).handleVisibility(m);
  }

  @Test
  void handleMessage_whenDisconnect_expectFinishDisconnectEffects() {
    // Arrange ticker to capture the scheduled runnable and run it synchronously
    AtomicReference<Runnable> scheduled = new AtomicReference<>();
    doAnswer(
            inv -> {
              scheduled.set(inv.getArgument(0));
              return null;
            })
        .when(ticker)
        .queueTimedJob(any(Runnable.class), anyLong());

    PeerNode src = peerMock();
    Message m = new Message(DMT.FNPDisconnect);
    m.set(DMT.REMOVE, true);
    m.set(DMT.PURGE, false);
    m.set(DMT.NODE_TO_NODE_MESSAGE_TYPE, 9);
    m.set(DMT.NODE_TO_NODE_MESSAGE_DATA, new ShortBuffer(new byte[] {1}));
    m = withSource(m, src);

    PeerManager pm = mock(PeerManager.class);
    PeerMessenger messenger = mock(PeerMessenger.class);
    when(node.getPeers()).thenReturn(pm);
    when(pm.messenger()).thenReturn(messenger);

    boolean handled = dispatcher.handleMessage(m);
    assertTrue(handled);

    // Execute the scheduled finishDisconnect() work
    scheduled.get().run();

    verify(src).disconnected(true, true);
    verify(messenger).disconnectAndRemove(src, false, false, false);
    verify(node).receivedNodeToNodeMessage(eq(src), eq(9), any(ShortBuffer.class), eq(true));
  }

  @Test
  void handleMessage_whenNonRoutableAndNonRequest_expectFalse() {
    PeerNode src = peerMock();
    when(src.isRoutable()).thenReturn(false);
    Message m = withSource(DMT.createFNPGetYourFullNoderef(), src);

    assertFalse(dispatcher.handleMessage(m));
  }

  @Test
  void handleMessage_whenNonRoutableChkRequest_expectRejectAndTrue() throws NotConnectedException {
    PeerNode src = peerMock();
    when(src.isRoutable()).thenReturn(false);
    NodeCHK key = new NodeCHK(new byte[NodeCHK.KEY_LENGTH], (byte) 1);
    Message m = withSource(DMT.createFNPCHKDataRequest(123L, (short) 3, key), src);

    assertTrue(dispatcher.handleMessage(m));
    verify(src).sendAsync(msgCaptor.capture(), eq(null), eq(stats.chkRequestCtr));
    Message rejected = msgCaptor.getValue();
    assertEquals(DMT.FNPRejectedOverload, rejected.getSpec());
    assertEquals(123L, rejected.getLong(DMT.UID));
  }

  @Test
  void setHook_whenCallbackSet_expectSnoopInvokedOnMessage() {
    PeerNode src = peerMock();
    Message m = withSource(DMT.createFNPVoid(), src);

    NodeDispatcherCallback cb = mock(NodeDispatcherCallback.class);
    dispatcher.setHook(cb);

    assertTrue(dispatcher.handleMessage(m));
    verify(cb).snoop(m, node);
  }

  @Test
  void start_whenInvoked_expectQueueRunnerSubmitted() {
    when(node.getExecutor()).thenReturn(executor);
    dispatcher.start(stats);
    verify(executor).execute(any(Runnable.class));
  }

  // ---- Routed-to-node handling ----

  @Test
  void handleRouted_whenTargetsLocal_expectPongSent() throws NotConnectedException {
    when(node.enableRoutedPing()).thenReturn(true);

    LocationManager lm = mock(LocationManager.class);
    when(lm.getLocation()).thenReturn(0.5);
    when(node.getLocationManager()).thenReturn(lm);

    PeerNode src = peerMock();
    when(src.decrementHTL(anyShort())).thenAnswer(i -> (short) ((short) i.getArgument(0) - 1));

    long uid = 42L;
    Message routedPing = DMT.createFNPRoutedPing(uid, 0.5, (short) 3, 7, new byte[] {9});
    routedPing = withSource(routedPing, src);

    dispatcher.handleRouted(routedPing, src);
    // Expect immediate pong to the source with same uid/counter
    verify(src).sendAsync(msgCaptor.capture(), eq(null), eq(stats.routedMessageCtr));
    Message sent = msgCaptor.getValue();
    assertEquals(DMT.FNPRoutedPong, sent.getSpec());
    assertEquals(uid, sent.getLong(DMT.UID));
    assertEquals(7, sent.getInt(DMT.COUNTER));
  }

  @Test
  void handleRouted_whenDuplicateId_expectRejectedSent() throws NotConnectedException {
    when(node.enableRoutedPing()).thenReturn(true);
    LocationManager lm = mock(LocationManager.class);
    when(lm.getLocation()).thenReturn(0.0);
    when(node.getLocationManager()).thenReturn(lm);

    PeerNode src = peerMock();
    long uid = 99L;
    Message first = DMT.createFNPRoutedPing(uid, 1.0, (short) 2, 1, new byte[] {1});
    first = withSource(first, src);
    dispatcher.handleRouted(first, src);

    Message dup = DMT.createFNPRoutedPing(uid, 1.0, (short) 2, 2, new byte[] {1});
    dup = withSource(dup, src);
    dispatcher.handleRouted(dup, src);

    verify(src, times(2)).sendAsync(msgCaptor.capture(), eq(null), eq(stats.routedMessageCtr));
    Message last = msgCaptor.getAllValues().get(1);
    assertEquals(DMT.FNPRoutedRejected, last.getSpec());
    assertEquals(uid, last.getLong(DMT.UID));
  }

  @Test
  void handleRoutedReply_whenContextExists_expectForwardedToSource() throws NotConnectedException {
    when(node.enableRoutedPing()).thenReturn(true);
    LocationManager lm = mock(LocationManager.class);
    when(lm.getLocation()).thenReturn(0.5);
    when(node.getLocationManager()).thenReturn(lm);

    PeerNode src = peerMock();
    long uid = 7L;
    Message routed = DMT.createFNPRoutedPing(uid, 0.5, (short) 2, 3, new byte[] {4});
    routed = withSource(routed, src);
    dispatcher.handleRouted(routed, src);

    Message reply = DMT.createFNPRoutedPong(uid, 3);
    assertTrue(dispatcher.handleRoutedReply(reply));
    verify(src, times(2)).sendAsync(any(Message.class), eq(null), eq(stats.routedMessageCtr));
  }

  // ---- UOM delegation ----

  @Test
  void uomAnnouncement_whenRealConnection_expectDelegated() {
    PeerNode src = peerMock();
    Message ann =
        new DMT.UOMAnnouncementBuilder()
            .mainKey("K")
            .revocationKey("R")
            .haveRevocation(true)
            .mainJarVersion(1)
            .timeLastTriedRevocationFetch(0)
            .revocationDNFCount(0)
            .revocationKeyLength(1)
            .mainJarLength(1)
            .pingTime(10)
            .bwlimitDelayTime(0)
            .build();
    ann = withSource(ann, src);

    NodeUpdateManager upd = mock(NodeUpdateManager.class);
    UpdateOverMandatoryManager uom = mock(UpdateOverMandatoryManager.class);
    when(node.getNodeUpdater()).thenReturn(upd);
    when(upd.getUpdateOverMandatory()).thenReturn(uom);
    when(uom.handleAnnounce(any(Message.class), any(PeerNode.class))).thenReturn(true);

    assertTrue(dispatcher.handleMessage(ann));
    verify(uom).handleAnnounce(ann, src);
  }
}
