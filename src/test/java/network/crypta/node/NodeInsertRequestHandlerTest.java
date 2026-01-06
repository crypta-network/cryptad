package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.node.NodeStats.RejectReason;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeRoutingSubsystem;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.ShortBuffer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeInsertRequestHandlerTest {
  private static final ByteCounter CHK_INSERT_CTR = newNoopCounter();
  private static final ByteCounter SSK_INSERT_CTR = newNoopCounter();

  @Mock private Node node;
  @Mock private NodeNetworkSubsystem networkSubsystem;
  @Mock private NodeRoutingSubsystem routingSubsystem;
  @Mock private NodeStorageSubsystem storageSubsystem;
  @Mock private NodeGetPubkey nodeGetPubkey;
  @Mock private RequestTracker tracker;
  @Mock private NodeStats nodeStats;
  @Mock private PeerNode source;
  @Mock private PeerTransport transport;
  @Mock private PriorityAwareExecutor executor;
  @Mock private Message message;
  @Mock private NodeCHK chkKey;
  @Mock private NodeSSK sskKey;

  @BeforeEach
  void setUp() {
    setFinalField(nodeStats, "chkInsertCtr", CHK_INSERT_CTR);
    setFinalField(nodeStats, "sskInsertCtr", SSK_INSERT_CTR);
  }

  @Test
  void handle_whenUnrecognizedSpec_expectFalse() {
    when(message.getSpec()).thenReturn(DMT.FNPAccepted);
    stubNodeBasics();

    NodeInsertRequestHandler handler = new NodeInsertRequestHandler(node);

    boolean handled = handler.handle(message, source);

    assertFalse(handled);
    verifyNoInteractions(tracker, executor, transport);
  }

  @Test
  void handle_whenLockUidFails_expectRejectLoopSent() throws Exception {
    long uid = 10L;
    when(message.getSpec()).thenReturn(DMT.FNPInsertRequest);
    when(message.getLong(DMT.UID)).thenReturn(uid);
    when(message.getSubMessage(DMT.FNPRealTimeFlag)).thenReturn(null);
    stubNodeBasics();
    stubTransport();
    when(tracker.lockUID(eq(uid), eq(false), eq(true), eq(false), eq(false), eq(false), any()))
        .thenReturn(false);

    NodeInsertRequestHandler handler = new NodeInsertRequestHandler(node);

    boolean handled = handler.handle(message, source);

    assertTrue(handled);
    ArgumentCaptor<Message> msgCaptor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(msgCaptor.capture(), isNull(), eq(CHK_INSERT_CTR));
    Message rejected = msgCaptor.getValue();
    assertEquals(DMT.FNPRejectedLoop, rejected.getSpec());
    assertEquals(uid, rejected.getLong(DMT.UID));
    verifyNoInteractions(executor);

    ArgumentCaptor<InsertTag> tagCaptor = ArgumentCaptor.forClass(InsertTag.class);
    verify(tracker)
        .lockUID(
            eq(uid), eq(false), eq(true), eq(false), eq(false), eq(false), tagCaptor.capture());
    InsertTag tag = tagCaptor.getValue();
    assertFalse(tag.isSSK());
    assertFalse(tag.realTimeFlag);
    assertEquals(uid, tag.uid);
  }

  @Test
  void handle_whenOverloadHard_expectRejectedOverloadWithoutSoftSubMessage() throws Exception {
    long uid = 44L;
    when(message.getSpec()).thenReturn(DMT.FNPInsertRequest);
    when(message.getLong(DMT.UID)).thenReturn(uid);
    when(message.getSubMessage(DMT.FNPRealTimeFlag)).thenReturn(null);
    stubNodeBasics();
    stubTransport();
    when(tracker.lockUID(eq(uid), eq(false), eq(true), eq(false), eq(false), eq(false), any()))
        .thenReturn(true);
    when(nodeStats.shouldRejectRequest(
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            eq(source),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            any()))
        .thenReturn(new RejectReason("hard", false));

    NodeInsertRequestHandler handler = new NodeInsertRequestHandler(node);

    boolean handled = handler.handle(message, source);

    assertTrue(handled);
    ArgumentCaptor<Message> msgCaptor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(msgCaptor.capture(), isNull(), eq(CHK_INSERT_CTR));
    Message rejected = msgCaptor.getValue();
    assertEquals(DMT.FNPRejectedOverload, rejected.getSpec());
    assertEquals(uid, rejected.getLong(DMT.UID));
    assertTrue(rejected.getBoolean(DMT.IS_LOCAL));
    assertNull(rejected.getSubMessage(DMT.FNPRejectIsSoft));
    verifyNoInteractions(executor);
  }

  @Test
  void handle_whenOverloadSoft_expectRejectedOverloadWithSoftSubMessage() throws Exception {
    long uid = 45L;
    when(message.getSpec()).thenReturn(DMT.FNPInsertRequest);
    when(message.getLong(DMT.UID)).thenReturn(uid);
    when(message.getSubMessage(DMT.FNPRealTimeFlag)).thenReturn(null);
    stubNodeBasics();
    stubTransport();
    when(tracker.lockUID(eq(uid), eq(false), eq(true), eq(false), eq(false), eq(false), any()))
        .thenReturn(true);
    when(nodeStats.shouldRejectRequest(
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            eq(source),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            any()))
        .thenReturn(new RejectReason("soft", true));

    NodeInsertRequestHandler handler = new NodeInsertRequestHandler(node);

    boolean handled = handler.handle(message, source);

    assertTrue(handled);
    ArgumentCaptor<Message> msgCaptor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(msgCaptor.capture(), isNull(), eq(CHK_INSERT_CTR));
    Message rejected = msgCaptor.getValue();
    assertEquals(DMT.FNPRejectedOverload, rejected.getSpec());
    assertEquals(uid, rejected.getLong(DMT.UID));
    assertNotNull(rejected.getSubMessage(DMT.FNPRejectIsSoft));
    verifyNoInteractions(executor);
  }

  @Test
  void handle_whenOverloadSendFails_expectHandledTrue() throws Exception {
    long uid = 46L;
    when(message.getSpec()).thenReturn(DMT.FNPInsertRequest);
    when(message.getLong(DMT.UID)).thenReturn(uid);
    when(message.getSubMessage(DMT.FNPRealTimeFlag)).thenReturn(null);
    stubNodeBasics();
    stubTransport();
    when(tracker.lockUID(eq(uid), eq(false), eq(true), eq(false), eq(false), eq(false), any()))
        .thenReturn(true);
    when(nodeStats.shouldRejectRequest(
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            eq(source),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            any()))
        .thenReturn(new RejectReason("soft", true));
    doThrow(new NotConnectedException("nope"))
        .when(transport)
        .sendAsync(any(Message.class), isNull(), eq(CHK_INSERT_CTR));

    NodeInsertRequestHandler handler = new NodeInsertRequestHandler(node);

    boolean handled = handler.handle(message, source);

    assertTrue(handled);
    verify(transport).sendAsync(any(Message.class), isNull(), eq(CHK_INSERT_CTR));
    verifyNoInteractions(executor);
  }

  @Test
  void handle_whenSskInsertRequestNew_expectScheduledHandlerWithAdjustedHtlAndOptions() {
    long uid = 99L;
    when(message.getSpec()).thenReturn(DMT.FNPSSKInsertRequestNew);
    when(message.getLong(DMT.UID)).thenReturn(uid);
    when(message.getShort(DMT.HTL)).thenReturn((short) 0);
    when(message.getObject(DMT.FREENET_ROUTING_KEY)).thenReturn(sskKey);
    when(message.receivedByteCount()).thenReturn(12);
    stubNodeBasics();
    stubStorage();
    stubExecutor();
    when(routingSubsystem.canWriteDatastoreInsert(anyShort())).thenReturn(true);
    when(sskKey.getPubKeyHash()).thenReturn(new byte[] {1, 2, 3});
    when(nodeGetPubkey.getKey(any(), eq(false), eq(false), isNull())).thenReturn(null);
    when(tracker.lockUID(eq(uid), eq(true), eq(true), eq(false), eq(false), eq(true), any()))
        .thenReturn(true);
    when(nodeStats.shouldRejectRequest(
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            eq(source),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            any()))
        .thenReturn(null);
    when(message.getSubMessage(DMT.FNPSubInsertForkControl))
        .thenReturn(DMT.createFNPSubInsertForkControl(false));
    when(message.getSubMessage(DMT.FNPSubInsertPreferInsert))
        .thenReturn(DMT.createFNPSubInsertPreferInsert(true));
    when(message.getSubMessage(DMT.FNPSubInsertIgnoreLowBackoff))
        .thenReturn(DMT.createFNPSubInsertIgnoreLowBackoff(true));
    when(message.getSubMessage(DMT.FNPRealTimeFlag)).thenReturn(DMT.createFNPRealTimeFlag(true));

    NodeInsertRequestHandler handler = new NodeInsertRequestHandler(node);

    boolean handled = handler.handle(message, source);

    assertTrue(handled);
    verify(routingSubsystem).canWriteDatastoreInsert((short) 1);
    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
    ArgumentCaptor<String> nameCaptor = ArgumentCaptor.forClass(String.class);
    verify(executor).execute(runnableCaptor.capture(), nameCaptor.capture());
    assertEquals("SSKInsertHandler for " + uid + " on 19123", nameCaptor.getValue());

    SSKInsertHandler handlerTask = (SSKInsertHandler) runnableCaptor.getValue();
    assertSame(sskKey, handlerTask.key);
    assertSame(source, handlerTask.source);
    assertEquals(uid, handlerTask.uid);
    assertNull(getPrivateField(SSKInsertHandler.class, handlerTask, "data"));
    assertNull(getPrivateField(SSKInsertHandler.class, handlerTask, "headers"));
    assertEquals(
        Short.valueOf((short) 1), getPrivateField(SSKInsertHandler.class, handlerTask, "htl"));
    assertEquals(false, getPrivateField(SSKInsertHandler.class, handlerTask, "forkOnCacheable"));
    assertEquals(true, getPrivateField(SSKInsertHandler.class, handlerTask, "preferInsert"));
    assertEquals(true, getPrivateField(SSKInsertHandler.class, handlerTask, "ignoreLowBackoff"));
    assertEquals(true, getPrivateField(SSKInsertHandler.class, handlerTask, "realTimeFlag"));
  }

  @Test
  void handle_whenSskInsertRequest_expectScheduledHandlerWithDataAndHeaders() {
    long uid = 101L;
    byte[] data = new byte[] {7, 8, 9};
    byte[] headers = new byte[] {3, 4};
    when(message.getSpec()).thenReturn(DMT.FNPSSKInsertRequest);
    when(message.getLong(DMT.UID)).thenReturn(uid);
    when(message.getShort(DMT.HTL)).thenReturn((short) 2);
    when(message.getObject(DMT.FREENET_ROUTING_KEY)).thenReturn(sskKey);
    when(message.getObject(DMT.DATA)).thenReturn(new ShortBuffer(data));
    when(message.getObject(DMT.BLOCK_HEADERS)).thenReturn(new ShortBuffer(headers));
    when(message.receivedByteCount()).thenReturn(4);
    stubNodeBasics();
    stubStorage();
    stubExecutor();
    when(routingSubsystem.canWriteDatastoreInsert(anyShort())).thenReturn(true);
    when(sskKey.getPubKeyHash()).thenReturn(new byte[] {9, 9, 9});
    when(nodeGetPubkey.getKey(any(), eq(false), eq(false), isNull())).thenReturn(null);
    when(tracker.lockUID(eq(uid), eq(true), eq(true), eq(false), eq(false), eq(false), any()))
        .thenReturn(true);
    when(nodeStats.shouldRejectRequest(
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            eq(source),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            any()))
        .thenReturn(null);
    when(message.getSubMessage(DMT.FNPRealTimeFlag)).thenReturn(null);

    NodeInsertRequestHandler handler = new NodeInsertRequestHandler(node);

    boolean handled = handler.handle(message, source);

    assertTrue(handled);
    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(executor).execute(runnableCaptor.capture(), any());
    SSKInsertHandler handlerTask = (SSKInsertHandler) runnableCaptor.getValue();
    assertSame(sskKey, handlerTask.key);
    assertEquals(uid, handlerTask.uid);
    assertSame(data, getPrivateField(SSKInsertHandler.class, handlerTask, "data"));
    assertSame(headers, getPrivateField(SSKInsertHandler.class, handlerTask, "headers"));
    assertEquals(
        Short.valueOf((short) 2), getPrivateField(SSKInsertHandler.class, handlerTask, "htl"));
  }

  @Test
  void handle_whenChkInsertRequest_expectScheduledHandlerWithAdjustedHtl() {
    long uid = 202L;
    when(message.getSpec()).thenReturn(DMT.FNPInsertRequest);
    when(message.getLong(DMT.UID)).thenReturn(uid);
    when(message.getShort(DMT.HTL)).thenReturn((short) 0);
    when(message.getObject(DMT.FREENET_ROUTING_KEY)).thenReturn(chkKey);
    when(message.receivedByteCount()).thenReturn(3);
    stubNodeBasics();
    stubExecutor();
    when(routingSubsystem.canWriteDatastoreInsert(anyShort())).thenReturn(true);
    when(tracker.lockUID(eq(uid), eq(false), eq(true), eq(false), eq(false), eq(false), any()))
        .thenReturn(true);
    when(nodeStats.shouldRejectRequest(
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            eq(source),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            any()))
        .thenReturn(null);
    when(message.getSubMessage(DMT.FNPRealTimeFlag)).thenReturn(null);

    NodeInsertRequestHandler handler = new NodeInsertRequestHandler(node);

    boolean handled = handler.handle(message, source);

    assertTrue(handled);
    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(executor).execute(runnableCaptor.capture(), any());
    CHKInsertHandler handlerTask = (CHKInsertHandler) runnableCaptor.getValue();
    assertSame(chkKey, handlerTask.key);
    assertEquals(uid, handlerTask.uid);
    assertEquals(
        Short.valueOf((short) 1), getPrivateField(CHKInsertHandler.class, handlerTask, "htl"));
    assertEquals(
        Node.FORK_ON_CACHEABLE_DEFAULT,
        getPrivateField(CHKInsertHandler.class, handlerTask, "forkOnCacheable"));
    assertEquals(
        Node.PREFER_INSERT_DEFAULT,
        getPrivateField(CHKInsertHandler.class, handlerTask, "preferInsert"));
    assertEquals(
        Node.IGNORE_LOW_BACKOFF_DEFAULT,
        getPrivateField(CHKInsertHandler.class, handlerTask, "ignoreLowBackoff"));
  }

  private static ByteCounter newNoopCounter() {
    return new ByteCounter() {
      @Override
      public void sentBytes(int x) {
        // No-op: tests only assert identity for the counter instance.
      }

      @Override
      public void receivedBytes(int x) {
        // No-op: tests only assert identity for the counter instance.
      }

      @Override
      public void sentPayload(int x) {
        // No-op: tests only assert identity for the counter instance.
      }
    };
  }

  private void stubNodeBasics() {
    when(node.network()).thenReturn(networkSubsystem);
    when(node.routing()).thenReturn(routingSubsystem);
    when(networkSubsystem.stats()).thenReturn(nodeStats);
    when(routingSubsystem.tracker()).thenReturn(tracker);
  }

  private void stubExecutor() {
    when(networkSubsystem.executor()).thenReturn(executor);
    when(networkSubsystem.darknetPortNumber()).thenReturn(19123);
  }

  private void stubStorage() {
    when(node.storage()).thenReturn(storageSubsystem);
    when(storageSubsystem.getPubKey()).thenReturn(nodeGetPubkey);
  }

  private void stubTransport() {
    when(source.transport()).thenReturn(transport);
  }

  @SuppressWarnings("java:S3011")
  private static void setFinalField(Object target, String fieldName, Object value) {
    try {
      Field field = NodeStats.class.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new AssertionError("Failed to set field: " + fieldName, e);
    }
  }

  @SuppressWarnings("java:S3011")
  private static <T> T getPrivateField(Class<?> declaringClass, Object target, String fieldName) {
    try {
      Field field = declaringClass.getDeclaredField(fieldName);
      field.setAccessible(true);
      @SuppressWarnings("unchecked")
      T value = (T) field.get(target);
      return value;
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new AssertionError("Failed to read field: " + fieldName, e);
    }
  }
}
