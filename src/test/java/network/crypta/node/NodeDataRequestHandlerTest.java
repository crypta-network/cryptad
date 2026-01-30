package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.ArrayBlockingQueue;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.node.NodeStats.RejectReason;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeRoutingSubsystem;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeDataRequestHandlerTest {

  private static final long REQUEST_ID = 42L;

  private Node node;
  private NodeNetworkSubsystem network;
  private NodeRoutingSubsystem routing;
  private NodeStorageSubsystem storage;
  private PriorityAwareExecutor executor;
  private RequestTracker tracker;
  private FailureTable failureTable;
  private ByteCounter chkCounter;
  private ByteCounter sskCounter;
  private NodeStats stats;
  private NodeDataRequestHandler handler;

  @BeforeEach
  void setUp() throws Exception {
    node = org.mockito.Mockito.mock(Node.class);
    network = org.mockito.Mockito.mock(NodeNetworkSubsystem.class);
    routing = org.mockito.Mockito.mock(NodeRoutingSubsystem.class);
    storage = org.mockito.Mockito.mock(NodeStorageSubsystem.class);
    executor = org.mockito.Mockito.mock(PriorityAwareExecutor.class);
    tracker = org.mockito.Mockito.mock(RequestTracker.class);
    failureTable = org.mockito.Mockito.mock(FailureTable.class);
    chkCounter = org.mockito.Mockito.mock(ByteCounter.class);
    sskCounter = org.mockito.Mockito.mock(ByteCounter.class);
    stats = statsWithCounters(chkCounter, sskCounter);

    when(node.network()).thenReturn(network);
    when(node.routing()).thenReturn(routing);
    when(network.stats()).thenReturn(stats);
    when(routing.tracker()).thenReturn(tracker);

    handler = new NodeDataRequestHandler(node);
  }

  @Test
  void handle_whenUnknownSpec_expectFalse() {
    Message message = org.mockito.Mockito.mock(Message.class);
    when(message.getSpec()).thenReturn(DMT.FNPRejectedOverload);

    boolean handled = handler.handle(message);

    assertFalse(handled);
  }

  @Test
  void handle_whenQueueFull_expectRejectOverloadSent() throws Exception {
    ArrayBlockingQueue<Message> queue = requestQueue(handler);
    //noinspection StatementWithEmptyBody
    while (queue.offer(org.mockito.Mockito.mock(Message.class))) {
      // Fill the queue to force the handler to reject the next offer deterministically.
    }

    PeerNode source = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    when(source.transport()).thenReturn(transport);

    Message message = org.mockito.Mockito.mock(Message.class);
    when(message.getSpec()).thenReturn(DMT.FNPCHKDataRequest);
    when(message.getLong(DMT.UID)).thenReturn(REQUEST_ID);
    when(message.getSource()).thenReturn(source);

    boolean handled = handler.handle(message);

    assertTrue(handled);
    ArgumentCaptor<Message> sent = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(sent.capture(), isNull(), eq(chkCounter));
    Message rejected = sent.getValue();
    assertSame(DMT.FNPRejectedOverload, rejected.getSpec());
    assertEquals(REQUEST_ID, rejected.getLong(DMT.UID));
    assertTrue(rejected.getBoolean(DMT.IS_LOCAL));
  }

  @Test
  void innerHandleDataRequest_whenSourceNotRoutable_expectOverloadRejected() throws Exception {
    PeerNode source = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    when(source.isConnected()).thenReturn(true);
    when(source.isRoutable()).thenReturn(false);
    when(source.transport()).thenReturn(transport);

    Message message = org.mockito.Mockito.mock(Message.class);
    when(message.getLong(DMT.UID)).thenReturn(REQUEST_ID);
    when(message.getSource()).thenReturn(source);

    invokeInnerHandle(handler, message, source, false);

    ArgumentCaptor<Message> sent = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(sent.capture(), isNull(), eq(chkCounter));
    assertSame(DMT.FNPRejectedOverload, sent.getValue().getSpec());
    verifyNoInteractions(tracker);
  }

  @Test
  void innerHandleDataRequest_whenLockAlreadyRunning_expectRejectLoopAndFailureTableNormalizedHtl()
      throws Exception {
    PeerNode source = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    Key key = org.mockito.Mockito.mock(Key.class);
    Message message = messageWithKey(key);
    when(source.isConnected()).thenReturn(true);
    when(source.isRoutable()).thenReturn(true);
    when(source.transport()).thenReturn(transport);
    when(message.getShort(DMT.HTL)).thenReturn((short) 0);
    when(message.getLong(DMT.UID)).thenReturn(REQUEST_ID);
    when(routing.failureTable()).thenReturn(failureTable);
    when(tracker.lockUID(
            eq(REQUEST_ID),
            eq(RequestAdmissionMode.of(false, false, false, false, false)),
            any(RequestTag.class)))
        .thenReturn(false);

    invokeInnerHandle(handler, message, source, false);

    ArgumentCaptor<Message> sent = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(sent.capture(), isNull(), eq(chkCounter));
    assertSame(DMT.FNPRejectedLoop, sent.getValue().getSpec());
    verify(failureTable)
        .onFinalFailure(
            eq(key), isNull(), eq((short) 1), eq((short) 1), eq(-1L), eq(-1L), eq(source));
    verifyNoInteractions(storage);
  }

  @Test
  @SuppressWarnings("ReferenceEquality")
  void innerHandleDataRequest_whenOverloadedSoft_expectRejectOverloadWithSoftSubMessage()
      throws Exception {
    PeerNode source = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    Key key = org.mockito.Mockito.mock(Key.class);
    when(source.isConnected()).thenReturn(true);
    when(source.isRoutable()).thenReturn(true);
    when(source.transport()).thenReturn(transport);

    Message message = messageWithKey(key);
    when(message.getLong(DMT.UID)).thenReturn(REQUEST_ID);
    when(message.getShort(DMT.HTL)).thenReturn((short) 5);

    when(node.storage()).thenReturn(storage);
    when(tracker.lockUID(
            eq(REQUEST_ID),
            eq(RequestAdmissionMode.of(false, false, false, false, false)),
            any(RequestTag.class)))
        .thenReturn(true);
    when(storage.fetch(eq(key), eq(false), eq(false), eq(false), eq(false), any()))
        .thenReturn(null);
    when(stats.shouldRejectRequest(
            argThat(
                context ->
                    context.canAcceptAnyway()
                        && !context.mode().isInsert()
                        && !context.mode().isSSK()
                        && !context.mode().isLocal()
                        && !context.mode().isOfferReply()
                        && context.source() == source
                        && !context.hasInStore()
                        && !context.preferInsert()
                        && !context.mode().realTimeFlag()
                        && context.tag() instanceof RequestTag)))
        .thenReturn(new RejectReason("overload", true));

    invokeInnerHandle(handler, message, source, false);

    ArgumentCaptor<Message> sent = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(sent.capture(), isNull(), eq(chkCounter));
    Message rejected = sent.getValue();
    assertSame(DMT.FNPRejectedOverload, rejected.getSpec());
    assertNotNull(rejected.getSubMessage(DMT.FNPRejectIsSoft));
    verify(stats, never()).reportIncomingRequestLocation(anyDouble());
    verify(executor, never()).execute(any(Runnable.class), any(String.class));
  }

  @Test
  void innerHandleDataRequest_whenAccepted_expectExecutesRequestHandlerAndReportsLocation()
      throws Exception {
    NodeStats updatedStats = statsWithCounters(chkCounter, sskCounter);
    when(updatedStats.shouldRejectRequest(any(RequestAdmissionContext.class))).thenReturn(null);

    when(network.executor()).thenReturn(executor);
    when(network.darknetPortNumber()).thenReturn(1234);
    handler.start(updatedStats);

    PeerNode source = org.mockito.Mockito.mock(PeerNode.class);
    NodeSSK key = org.mockito.Mockito.mock(NodeSSK.class);
    when(source.isConnected()).thenReturn(true);
    when(source.isRoutable()).thenReturn(true);
    when(key.toNormalizedDouble()).thenReturn(0.42);

    Message message = messageWithKey(key);
    when(message.getLong(DMT.UID)).thenReturn(REQUEST_ID);
    when(message.getShort(DMT.HTL)).thenReturn((short) 2);
    when(message.getBoolean(DMT.NEED_PUB_KEY)).thenReturn(true);

    when(node.storage()).thenReturn(storage);
    when(tracker.lockUID(
            eq(REQUEST_ID),
            eq(RequestAdmissionMode.of(false, true, false, false, false)),
            any(RequestTag.class)))
        .thenReturn(true);
    when(storage.fetch(eq(key), eq(false), eq(false), eq(false), eq(false), any()))
        .thenReturn(org.mockito.Mockito.mock(KeyBlock.class));

    invokeInnerHandle(handler, message, source, true);

    verify(updatedStats).reportIncomingRequestLocation(0.42);
    ArgumentCaptor<Runnable> handlerRunnable = ArgumentCaptor.forClass(Runnable.class);
    verify(executor).execute(handlerRunnable.capture(), eq("RequestHandler for UID 42 on 1234"));
    assertInstanceOf(RequestHandler.class, handlerRunnable.getValue());
    assertTrue(needsPubKey(handlerRunnable.getValue()));
  }

  private static Message messageWithKey(Key key) {
    Message message = org.mockito.Mockito.mock(Message.class);
    when(message.getObject(DMT.FREENET_ROUTING_KEY)).thenReturn(key);
    when(message.getSubMessage(DMT.FNPRealTimeFlag)).thenReturn(null);
    return message;
  }

  private static ArrayBlockingQueue<Message> requestQueue(NodeDataRequestHandler handler)
      throws Exception {
    Field field = NodeDataRequestHandler.class.getDeclaredField("requestQueue");
    field.setAccessible(true);
    @SuppressWarnings("unchecked")
    ArrayBlockingQueue<Message> queue = (ArrayBlockingQueue<Message>) field.get(handler);
    return queue;
  }

  private static void invokeInnerHandle(
      NodeDataRequestHandler handler, Message message, PeerNode source, boolean isSSK)
      throws Exception {
    Field field = NodeDataRequestHandler.class.getDeclaredField("queueRunner");
    field.setAccessible(true);
    Object runner = field.get(handler);
    Method method =
        runner
            .getClass()
            .getDeclaredMethod(
                "innerHandleDataRequest", Message.class, PeerNode.class, boolean.class);
    method.setAccessible(true);
    method.invoke(runner, message, source, isSSK);
  }

  private static NodeStats statsWithCounters(ByteCounter chk, ByteCounter ssk) throws Exception {
    NodeStats stats = org.mockito.Mockito.mock(NodeStats.class);
    setField(stats, "chkRequestCtr", chk);
    setField(stats, "sskRequestCtr", ssk);
    return stats;
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception {
    Field field = NodeStats.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static boolean needsPubKey(Object handler) throws Exception {
    Field field = RequestHandler.class.getDeclaredField("needsPubKey");
    field.setAccessible(true);
    return (boolean) field.get(handler);
  }
}
