package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.stream.Stream;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeRoutingSubsystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeNotRoutableHandlerTest {
  private static final ByteCounter CHK_REQUEST_CTR = newNoopCounter();
  private static final ByteCounter SSK_REQUEST_CTR = newNoopCounter();
  private static final ByteCounter CHK_INSERT_CTR = newNoopCounter();
  private static final ByteCounter SSK_INSERT_CTR = newNoopCounter();
  private static final ByteCounter OFFERED_KEY_CTR = newNoopCounter();

  @Mock private Node node;
  @Mock private NodeNetworkSubsystem networkSubsystem;
  @Mock private NodeRoutingSubsystem routingSubsystem;
  @Mock private NodeStats stats;
  @Mock private FailureTable failureTable;
  @Mock private Message message;
  @Mock private PeerContext peerContext;
  @Mock private PeerTransport transport;

  @BeforeEach
  void setUp() {
    setFinalField(stats, NodeStats.class, "chkRequestCtr", CHK_REQUEST_CTR);
    setFinalField(stats, NodeStats.class, "sskRequestCtr", SSK_REQUEST_CTR);
    setFinalField(stats, NodeStats.class, "chkInsertCtr", CHK_INSERT_CTR);
    setFinalField(stats, NodeStats.class, "sskInsertCtr", SSK_INSERT_CTR);
    setFinalField(failureTable, FailureTable.class, "senderCounter", OFFERED_KEY_CTR);
  }

  @ParameterizedTest
  @MethodSource("rejectableMessageTypes")
  void handle_whenRejectableSpec_expectRejectionSent(MessageType spec, ByteCounter expectedCtr)
      throws Exception {
    long uid = 42L;
    when(message.getSpec()).thenReturn(spec);
    when(message.getLong(DMT.UID)).thenReturn(uid);
    if (spec == DMT.FNPGetOfferedKey) {
      prepareRoutingFailureTable();
    } else {
      prepareNetworkStats();
    }
    prepareMessageSource();

    NodeNotRoutableHandler handler = new NodeNotRoutableHandler(node);

    boolean handled = handler.handle(message);

    assertTrue(handled);
    ArgumentCaptor<Message> msgCaptor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(msgCaptor.capture(), isNull(), eq(expectedCtr));

    Message sent = msgCaptor.getValue();
    assertAll(
        () -> assertEquals(DMT.FNPRejectedOverload, sent.getSpec()),
        () -> assertEquals(uid, sent.getLong(DMT.UID)),
        () -> assertTrue(sent.getBoolean(DMT.IS_LOCAL)));
  }

  @Test
  void handle_whenUnhandledSpec_expectFalse() {
    when(message.getSpec()).thenReturn(DMT.FNPAccepted);

    NodeNotRoutableHandler handler = new NodeNotRoutableHandler(node);

    boolean handled = handler.handle(message);

    assertFalse(handled);
    verifyNoInteractions(transport);
  }

  @Test
  void handle_whenSendAsyncThrowsNotConnected_expectTrue() throws Exception {
    when(message.getSpec()).thenReturn(DMT.FNPCHKDataRequest);
    when(message.getLong(DMT.UID)).thenReturn(7L);
    prepareNetworkStats();
    prepareMessageSource();
    doThrow(new NotConnectedException("test"))
        .when(transport)
        .sendAsync(any(Message.class), isNull(), eq(CHK_REQUEST_CTR));

    NodeNotRoutableHandler handler = new NodeNotRoutableHandler(node);

    boolean handled = handler.handle(message);

    assertTrue(handled);
    verify(transport).sendAsync(any(Message.class), isNull(), eq(CHK_REQUEST_CTR));
  }

  static Stream<Arguments> rejectableMessageTypes() {
    return Stream.of(
        Arguments.of(DMT.FNPCHKDataRequest, CHK_REQUEST_CTR),
        Arguments.of(DMT.FNPSSKDataRequest, SSK_REQUEST_CTR),
        Arguments.of(DMT.FNPInsertRequest, CHK_INSERT_CTR),
        Arguments.of(DMT.FNPSSKInsertRequest, SSK_INSERT_CTR),
        Arguments.of(DMT.FNPSSKInsertRequestNew, SSK_INSERT_CTR),
        Arguments.of(DMT.FNPGetOfferedKey, OFFERED_KEY_CTR));
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

  @SuppressWarnings("java:S3011")
  private static void setFinalField(
      Object target, Class<?> declaringClass, String fieldName, Object value) {
    try {
      Field field = declaringClass.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new AssertionError("Failed to set field: " + fieldName, e);
    }
  }

  private void prepareNetworkStats() {
    when(node.network()).thenReturn(networkSubsystem);
    when(networkSubsystem.stats()).thenReturn(stats);
  }

  private void prepareRoutingFailureTable() {
    when(node.routing()).thenReturn(routingSubsystem);
    when(routingSubsystem.failureTable()).thenReturn(failureTable);
  }

  private void prepareMessageSource() {
    when(message.getSource()).thenReturn(peerContext);
    when(peerContext.transport()).thenReturn(transport);
  }
}
