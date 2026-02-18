package network.crypta.node;

import java.lang.reflect.Field;
import java.util.Map;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.Peer;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.support.PrioritizedTicker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "java:S3011"})
class NodeRoutedMessageRouterTest {

  private static final long UID = 42L;
  private static final double TARGET = 0.42d;
  private static final short HTL = 3;
  private static final int COUNTER = 7;
  private static final byte[] IDENTITY = new byte[] {1, 2, 3, 4};

  @Mock private Node node;
  @Mock private NodeNetworkSubsystem network;
  @Mock private MessageCore messageCore;
  @Mock private PrioritizedTicker ticker;
  @Mock private NodeStats nodeStats;
  @Mock private PeerManager peerManager;
  @Mock private PeerRoutingSelector routingSelector;
  @Mock private LocationManager locationManager;
  @Mock private PeerNode source;
  @Mock private PeerTransport sourceTransport;
  @Mock private PeerNode nextHop;
  @Mock private PeerTransport nextTransport;
  @Mock private Peer peer;

  @Captor private ArgumentCaptor<Message> messageCaptor;
  @Captor private ArgumentCaptor<AsyncMessageCallback> callbackCaptor;
  @Captor private ArgumentCaptor<ByteCounter> counterCaptor;

  @BeforeEach
  void setUp() {
    when(node.network()).thenReturn(network);
    when(network.stats()).thenReturn(nodeStats);
    when(network.ticker()).thenReturn(ticker);
  }

  @Test
  void handle_whenUnknownSpec_returnsFalse() {
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    MessageType otherType = DMT.FNPDetectedIPAddress;
    Message message = new Message(otherType);

    boolean handled = router.handle(message, source);

    assertFalse(handled);
  }

  @Test
  void handleRouted_whenLocalTarget_dispatchesPongToSource() throws Exception {
    when(node.enableRoutedPing()).thenReturn(true);
    when(network.locationManager()).thenReturn(locationManager);
    when(source.transport()).thenReturn(sourceTransport);
    when(network.darknetPortNumber()).thenReturn(1337);
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    when(locationManager.getLocation()).thenReturn(TARGET);
    Message ping = DMT.createFNPRoutedPing(UID, TARGET, HTL, COUNTER, IDENTITY);

    router.handleRouted(ping, source);

    Message reply = captureSent(sourceTransport);
    assertEquals(DMT.FNPRoutedPong, reply.getSpec());
    assertEquals(UID, reply.getLong(DMT.UID));
    assertEquals(COUNTER, reply.getInt(DMT.COUNTER));
  }

  @Test
  void handleRouted_whenLocalTargetAndLocalOrigin_dispatchesPongToMessageCore() {
    when(node.enableRoutedPing()).thenReturn(true);
    when(network.locationManager()).thenReturn(locationManager);
    when(network.usm()).thenReturn(messageCore);
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    when(locationManager.getLocation()).thenReturn(TARGET);
    Message ping = DMT.createFNPRoutedPing(UID, TARGET, HTL, COUNTER, IDENTITY);

    router.handleRouted(ping, null);

    verify(messageCore).checkFilters(messageCaptor.capture(), isNull());
    Message reply = messageCaptor.getValue();
    assertEquals(DMT.FNPRoutedPong, reply.getSpec());
    assertEquals(UID, reply.getLong(DMT.UID));
    assertEquals(COUNTER, reply.getInt(DMT.COUNTER));
  }

  @Test
  void handleRouted_whenHtlZeroAndNotLocal_sendsRejected() throws Exception {
    when(node.enableRoutedPing()).thenReturn(true);
    when(network.locationManager()).thenReturn(locationManager);
    when(source.transport()).thenReturn(sourceTransport);
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    when(locationManager.getLocation()).thenReturn(0.99d);
    Message ping = DMT.createFNPRoutedPing(UID, TARGET, (short) 0, COUNTER, IDENTITY);

    router.handleRouted(ping, source);

    Message reject = captureSent(sourceTransport);
    assertEquals(DMT.FNPRoutedRejected, reject.getSpec());
    assertEquals(UID, reject.getLong(DMT.UID));
    assertEquals(0, reject.getShort(DMT.HTL));
  }

  @Test
  void handleRouted_whenDuplicateId_sendsRejectedWithAdjustedHtl() throws Exception {
    when(node.enableRoutedPing()).thenReturn(true);
    when(source.transport()).thenReturn(sourceTransport);
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    when(source.decrementHTL(HTL)).thenReturn((short) 2);
    Message ping = DMT.createFNPRoutedPing(UID, TARGET, HTL, COUNTER, IDENTITY);
    NodeRoutedMessageRouter.RoutedContext ctx =
        new NodeRoutedMessageRouter.RoutedContext(ping, source, IDENTITY);
    routedContexts(router).put(UID, ctx);

    router.handleRouted(ping, source);

    Message reject = captureSent(sourceTransport);
    assertEquals(DMT.FNPRoutedRejected, reject.getSpec());
    assertEquals(UID, reject.getLong(DMT.UID));
    assertEquals(2, reject.getShort(DMT.HTL));
  }

  @Test
  void handleRouted_whenForwarding_updatesHtlAndCounterAndSendsToTarget() throws Exception {
    when(node.enableRoutedPing()).thenReturn(true);
    when(network.locationManager()).thenReturn(locationManager);
    when(network.peers()).thenReturn(peerManager);
    when(nextHop.transport()).thenReturn(nextTransport);
    when(nextHop.isConnected()).thenReturn(true);
    lenient().when(nextHop.getPeer()).thenReturn(peer);
    lenient().when(peer.getPort()).thenReturn(9999);
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    when(locationManager.getLocation()).thenReturn(0.99d);
    when(source.decrementHTL(HTL)).thenReturn((short) 2);
    when(peerManager.getByPubKeyHash(IDENTITY)).thenReturn(nextHop);
    Message ping = DMT.createFNPRoutedPing(UID, TARGET, HTL, COUNTER, IDENTITY);

    router.handleRouted(ping, source);

    Message forwarded = captureSent(nextTransport);
    assertEquals(DMT.FNPRoutedPing, forwarded.getSpec());
    assertEquals(UID, forwarded.getLong(DMT.UID));
    assertEquals(2, forwarded.getShort(DMT.HTL));
    assertEquals(COUNTER + 1, forwarded.getInt(DMT.COUNTER));
  }

  @Test
  void handleRoutedReply_withContextForwardsToSource() throws Exception {
    when(node.enableRoutedPing()).thenReturn(true);
    when(source.transport()).thenReturn(sourceTransport);
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    Message pong = DMT.createFNPRoutedPong(UID, COUNTER);
    Message original = DMT.createFNPRoutedPing(UID, TARGET, HTL, COUNTER, IDENTITY);
    NodeRoutedMessageRouter.RoutedContext ctx =
        new NodeRoutedMessageRouter.RoutedContext(original, source, IDENTITY);
    routedContexts(router).put(UID, ctx);

    boolean handled = router.handleRoutedReply(pong);

    assertTrue(handled);
    Message forwarded = captureSent(sourceTransport);
    assertEquals(DMT.FNPRoutedPong, forwarded.getSpec());
    assertEquals(UID, forwarded.getLong(DMT.UID));
    assertNotSame(pong, forwarded);
  }

  @Test
  void handleRoutedReply_withoutContext_returnsFalse() {
    when(node.enableRoutedPing()).thenReturn(true);
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    Message pong = DMT.createFNPRoutedPong(UID, COUNTER);

    boolean handled = router.handleRoutedReply(pong);

    assertFalse(handled);
    verifyNoInteractions(sourceTransport);
  }

  @Test
  void handleRoutedRejected_whenHtlBecomesZero_relaysRejected() throws Exception {
    when(node.enableRoutedPing()).thenReturn(true);
    when(source.transport()).thenReturn(sourceTransport);
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    when(source.decrementHTL((short) 1)).thenReturn((short) 0);
    Message original = DMT.createFNPRoutedPing(UID, TARGET, (short) 1, COUNTER, IDENTITY);
    NodeRoutedMessageRouter.RoutedContext ctx =
        new NodeRoutedMessageRouter.RoutedContext(original, source, IDENTITY);
    ctx.lastHtl = 1;
    routedContexts(router).put(UID, ctx);
    Message reject = DMT.createFNPRoutedRejected(UID, (short) 5);

    boolean handled = router.handle(reject, null);

    assertTrue(handled);
    Message forwardedReject = captureSent(sourceTransport);
    assertEquals(DMT.FNPRoutedRejected, forwardedReject.getSpec());
    assertEquals(UID, forwardedReject.getLong(DMT.UID));
    assertEquals(0, forwardedReject.getShort(DMT.HTL));
  }

  @Test
  void handleRoutedRejected_whenNoNextHop_sendsDeadEndReject() throws Exception {
    when(node.enableRoutedPing()).thenReturn(true);
    when(network.peers()).thenReturn(peerManager);
    when(peerManager.routingSelector()).thenReturn(routingSelector);
    when(node.isAdvancedModeEnabled()).thenReturn(false);
    when(source.transport()).thenReturn(sourceTransport);
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    when(source.decrementHTL((short) 2)).thenReturn((short) 1);
    when(peerManager.getByPubKeyHash(IDENTITY)).thenReturn(null);
    Message original = DMT.createFNPRoutedPing(UID, TARGET, (short) 2, COUNTER, IDENTITY);
    NodeRoutedMessageRouter.RoutedContext ctx =
        new NodeRoutedMessageRouter.RoutedContext(original, source, IDENTITY);
    ctx.lastHtl = 2;
    routedContexts(router).put(UID, ctx);
    when(routingSelector.closerPeer(any(PeerRoutingSelectionParams.class))).thenReturn(null);
    Message reject = DMT.createFNPRoutedRejected(UID, (short) 5);

    boolean handled = router.handle(reject, null);

    assertTrue(handled);
    Message forwardedReject = captureSent(sourceTransport);
    assertEquals(DMT.FNPRoutedRejected, forwardedReject.getSpec());
    assertEquals(UID, forwardedReject.getLong(DMT.UID));
    assertEquals(1, forwardedReject.getShort(DMT.HTL));
  }

  @Test
  void handleRoutedRejected_whenContextMissing_returnsFalse() {
    when(node.enableRoutedPing()).thenReturn(true);
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    Message reject = DMT.createFNPRoutedRejected(UID, (short) 1);

    boolean handled = router.handle(reject, null);

    assertFalse(handled);
  }

  @Test
  void run_prunesStaleContextsAndReschedules() {
    NodeRoutedMessageRouter router = new NodeRoutedMessageRouter(node);
    clearInvocations(ticker);
    Map<Long, NodeRoutedMessageRouter.RoutedContext> contexts = routedContexts(router);
    Message freshMsg = DMT.createFNPRoutedPing(UID, TARGET, HTL, COUNTER, IDENTITY);
    NodeRoutedMessageRouter.RoutedContext fresh =
        new NodeRoutedMessageRouter.RoutedContext(freshMsg, source, IDENTITY);
    Message staleMsg = DMT.createFNPRoutedPing(UID + 1, TARGET, HTL, COUNTER, IDENTITY);
    NodeRoutedMessageRouter.RoutedContext stale =
        new NodeRoutedMessageRouter.RoutedContext(staleMsg, source, IDENTITY);
    setCreatedTime(stale, System.currentTimeMillis() - 30000);
    contexts.put(UID, fresh);
    contexts.put(UID + 1, stale);

    router.run();

    assertEquals(1, contexts.size());
    assertNotNull(contexts.get(UID));
    verify(ticker, atLeastOnce()).queueTimedJob(router, 20000L);
  }

  private static Map<Long, NodeRoutedMessageRouter.RoutedContext> routedContexts(
      NodeRoutedMessageRouter router) {
    try {
      Field field = NodeRoutedMessageRouter.class.getDeclaredField("routedContexts");
      field.setAccessible(true);
      @SuppressWarnings("unchecked")
      Map<Long, NodeRoutedMessageRouter.RoutedContext> map =
          (Map<Long, NodeRoutedMessageRouter.RoutedContext>) field.get(router);
      return map;
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed to access routedContexts", e);
    }
  }

  private static void setCreatedTime(NodeRoutedMessageRouter.RoutedContext context, long value) {
    try {
      Field field = NodeRoutedMessageRouter.RoutedContext.class.getDeclaredField("createdTime");
      field.setAccessible(true);
      field.setLong(context, value);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed to set createdTime", e);
    }
  }

  private Message captureSent(PeerTransport transport) throws Exception {
    verify(transport)
        .sendAsync(messageCaptor.capture(), callbackCaptor.capture(), counterCaptor.capture());
    assertNull(callbackCaptor.getValue());
    assertSame(nodeStats.routedMessageCtr, counterCaptor.getValue());
    return messageCaptor.getValue();
  }
}
