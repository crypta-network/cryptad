package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import network.crypta.crypt.HMAC;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.Key;
import network.crypta.keys.NodeSSK;
import network.crypta.node.NodeStats.RejectReason;
import network.crypta.node.subsystem.NodeBootstrap;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeRoutingSubsystem;
import network.crypta.support.ShortBuffer;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class NodeOfferMessageHandlerTest {

  @Mock private Node node;
  @Mock private NodeRoutingSubsystem routing;
  @Mock private NodeNetworkSubsystem network;
  @Mock private NodeBootstrap bootstrap;
  @Mock private RandomSource randomSource;
  @Mock private Ticker ticker;
  @Mock private RequestTracker tracker;
  @Mock private NodeStats nodeStats;
  @Mock private PeerTransport transport;
  @Mock private PeerNode peer;

  private byte[] authenticatorKey;
  private NodeOfferMessageHandler handler;
  private FailureTable failureTable;

  @BeforeEach
  void setUp() throws Exception {
    when(node.routing()).thenReturn(routing);
    when(routing.tracker()).thenReturn(tracker);
    when(node.network()).thenReturn(network);
    when(network.stats()).thenReturn(nodeStats);
    when(network.ticker()).thenReturn(ticker);
    when(node.bootstrap()).thenReturn(bootstrap);
    when(bootstrap.random()).thenReturn(randomSource);

    failureTable = spy(new FailureTable(node));
    doNothing().when(failureTable).onOffer(any(), any(), any());
    doNothing()
        .when(failureTable)
        .sendOfferedKey(any(), anyBoolean(), anyBoolean(), anyLong(), any(), any(), anyBoolean());
    when(routing.failureTable()).thenReturn(failureTable);

    authenticatorKey = failureTable.offerAuthenticatorKey;
    handler = new NodeOfferMessageHandler(node);
  }

  @Test
  void handle_whenOfferKey_callsOnOfferAndReturnsTrue() {
    Key key = mock(Key.class);
    byte[] authenticator = new byte[] {1, 2, 3};
    Message msg = new Message(DMT.FNPOfferKey);
    msg.set(DMT.KEY, key);
    msg.set(DMT.OFFER_AUTHENTICATOR, new ShortBuffer(authenticator));

    boolean handled = handler.handle(msg, peer);

    assertTrue(handled);
    ArgumentCaptor<byte[]> authCaptor = ArgumentCaptor.forClass(byte[].class);
    verify(failureTable).onOffer(eq(key), eq(peer), authCaptor.capture());
    assertArrayEquals(authenticator, authCaptor.getValue());
  }

  @Test
  void handle_whenGetYourFullNoderefFromDarknet_callsSendFullNoderef() {
    DarknetPeerNode darknetPeer = mock(DarknetPeerNode.class);
    Message msg = new Message(DMT.FNPGetYourFullNoderef);

    boolean handled = handler.handle(msg, darknetPeer);

    assertTrue(handled);
    verify(darknetPeer).sendFullNoderef();
  }

  @Test
  void handle_whenMyFullNoderefFromDarknet_callsHandleFullNoderef() {
    DarknetPeerNode darknetPeer = mock(DarknetPeerNode.class);
    Message msg = new Message(DMT.FNPMyFullNoderef);

    boolean handled = handler.handle(msg, darknetPeer);

    assertTrue(handled);
    verify(darknetPeer).handleFullNoderef(msg);
  }

  @Test
  void handle_whenUnknownMessage_returnsFalse() {
    Message msg = new Message(DMT.FNPPing);

    boolean handled = handler.handle(msg, peer);

    assertFalse(handled);
  }

  @Test
  void handle_whenGetOfferedKeyInvalidAuthenticator_sendsInvalidAndDoesNotLock() throws Exception {
    Key key = mock(Key.class);
    byte[] keyBytes = new byte[] {10, 11, 12};
    when(key.getFullKey()).thenReturn(keyBytes);
    byte[] invalidAuthenticator = new byte[32];
    long uid = 42L;
    Message msg = offeredKeyMessage(key, invalidAuthenticator, uid, false, false);

    when(peer.transport()).thenReturn(transport);
    doReturn(null)
        .when(transport)
        .sendAsync(any(Message.class), isNull(), same(failureTable.senderCounter));

    boolean handled = handler.handle(msg, peer);

    assertTrue(handled);
    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(transport)
        .sendAsync(messageCaptor.capture(), isNull(), same(failureTable.senderCounter));
    Message sent = messageCaptor.getValue();
    assertEquals(DMT.FNPGetOfferedKeyInvalid, sent.getSpec());
    assertEquals(uid, sent.getLong(DMT.UID));
    assertEquals(DMT.GET_OFFERED_KEY_REJECTED_BAD_AUTHENTICATOR, sent.getShort(DMT.REASON));
    verify(tracker, never()).lockUID(anyLong(), any(RequestAdmissionMode.class), any());
    verify(failureTable, never())
        .sendOfferedKey(
            any(Key.class), anyBoolean(), anyBoolean(), anyLong(), any(), any(), anyBoolean());
  }

  @Test
  void handle_whenGetOfferedKeyLockContended_sendsRejectedLoop() throws Exception {
    Key key = mock(Key.class);
    byte[] keyBytes = new byte[] {1, 2, 3, 4};
    when(key.getFullKey()).thenReturn(keyBytes);
    byte[] authenticator = validAuthenticatorFor(keyBytes);
    long uid = 99L;
    Message msg = offeredKeyMessage(key, authenticator, uid, false, false);

    when(peer.transport()).thenReturn(transport);
    doReturn(null)
        .when(transport)
        .sendAsync(any(Message.class), isNull(), same(failureTable.senderCounter));
    when(tracker.lockUID(
            eq(uid), eq(RequestAdmissionMode.of(false, false, false, true, false)), any()))
        .thenReturn(false);

    boolean handled = handler.handle(msg, peer);

    assertTrue(handled);
    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(transport)
        .sendAsync(messageCaptor.capture(), isNull(), same(failureTable.senderCounter));
    Message sent = messageCaptor.getValue();
    assertEquals(DMT.FNPRejectedLoop, sent.getSpec());
    assertEquals(uid, sent.getLong(DMT.UID));
    verify(failureTable, never())
        .sendOfferedKey(
            any(Key.class), anyBoolean(), anyBoolean(), anyLong(), any(), any(), anyBoolean());
  }

  @Test
  @SuppressWarnings("ReferenceEquality")
  void handle_whenGetOfferedKeyRejectedSoft_sendsOverloadWithSoftMarker() throws Exception {
    Key key = mock(Key.class);
    byte[] keyBytes = new byte[] {5, 6, 7, 8};
    when(key.getFullKey()).thenReturn(keyBytes);
    byte[] authenticator = validAuthenticatorFor(keyBytes);
    long uid = 123L;
    Message msg = offeredKeyMessage(key, authenticator, uid, true, false);

    when(peer.transport()).thenReturn(transport);
    doReturn(null)
        .when(transport)
        .sendAsync(any(Message.class), isNull(), same(failureTable.senderCounter));
    when(tracker.lockUID(
            eq(uid), eq(RequestAdmissionMode.of(false, false, false, true, false)), any()))
        .thenReturn(true);
    when(nodeStats.shouldRejectRequest(
            argThat(
                context ->
                    context.canAcceptAnyway()
                        && !context.mode().isInsert()
                        && !context.mode().isSSK()
                        && !context.mode().isLocal()
                        && context.mode().isOfferReply()
                        && context.source() == peer
                        && !context.hasInStore()
                        && !context.preferInsert()
                        && !context.mode().realTimeFlag()
                        && context.tag() instanceof OfferReplyTag)))
        .thenReturn(new RejectReason("overload", true));

    boolean handled = handler.handle(msg, peer);

    assertTrue(handled);
    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(transport)
        .sendAsync(messageCaptor.capture(), isNull(), same(failureTable.senderCounter));
    Message sent = messageCaptor.getValue();
    assertEquals(DMT.FNPRejectedOverload, sent.getSpec());
    assertNotNull(sent.getSubMessage(DMT.FNPRejectIsSoft));
    verify(failureTable, never())
        .sendOfferedKey(
            any(Key.class), anyBoolean(), anyBoolean(), anyLong(), any(), any(), anyBoolean());
  }

  @Test
  @SuppressWarnings("ReferenceEquality")
  void handle_whenGetOfferedKeyAccepted_callsSendOfferedKeyWithTag() throws Exception {
    NodeSSK key = mock(NodeSSK.class);
    byte[] keyBytes = new byte[] {9, 10, 11, 12};
    when(key.getFullKey()).thenReturn(keyBytes);
    byte[] authenticator = validAuthenticatorFor(keyBytes);
    long uid = 456L;
    Message msg = offeredKeyMessage(key, authenticator, uid, true, true);

    when(peer.transport()).thenReturn(transport);
    when(tracker.lockUID(
            eq(uid), eq(RequestAdmissionMode.of(false, true, false, true, true)), any()))
        .thenReturn(true);
    when(nodeStats.shouldRejectRequest(
            argThat(
                context ->
                    context.canAcceptAnyway()
                        && !context.mode().isInsert()
                        && context.mode().isSSK()
                        && !context.mode().isLocal()
                        && context.mode().isOfferReply()
                        && context.source() == peer
                        && !context.hasInStore()
                        && !context.preferInsert()
                        && context.mode().realTimeFlag()
                        && context.tag() instanceof OfferReplyTag)))
        .thenReturn(null);

    boolean handled = handler.handle(msg, peer);

    assertTrue(handled);
    ArgumentCaptor<OfferReplyTag> tagCaptor = ArgumentCaptor.forClass(OfferReplyTag.class);
    verify(failureTable)
        .sendOfferedKey(
            eq(key), eq(true), eq(true), eq(uid), eq(peer), tagCaptor.capture(), eq(true));
    OfferReplyTag tag = tagCaptor.getValue();
    assertEquals(uid, tag.uid);
    assertTrue(tag.realTimeFlag);
    assertTrue(tag.isSSK());
  }

  @Test
  @SuppressWarnings("ReferenceEquality")
  void start_whenNewStatsProvided_updatesShouldRejectRequestTarget() throws Exception {
    NodeStats replacementStats = mock(NodeStats.class);
    handler.start(replacementStats);

    Key key = mock(Key.class);
    byte[] keyBytes = new byte[] {20, 21, 22};
    when(key.getFullKey()).thenReturn(keyBytes);
    byte[] authenticator = validAuthenticatorFor(keyBytes);
    long uid = 88L;
    Message msg = offeredKeyMessage(key, authenticator, uid, false, false);

    when(peer.transport()).thenReturn(transport);
    doReturn(null)
        .when(transport)
        .sendAsync(any(Message.class), isNull(), same(failureTable.senderCounter));
    when(tracker.lockUID(
            eq(uid), eq(RequestAdmissionMode.of(false, false, false, true, false)), any()))
        .thenReturn(true);
    when(replacementStats.shouldRejectRequest(
            argThat(
                context ->
                    context.canAcceptAnyway()
                        && !context.mode().isInsert()
                        && !context.mode().isSSK()
                        && !context.mode().isLocal()
                        && context.mode().isOfferReply()
                        && context.source() == peer
                        && !context.hasInStore()
                        && !context.preferInsert()
                        && !context.mode().realTimeFlag()
                        && context.tag() instanceof OfferReplyTag)))
        .thenReturn(new RejectReason("rate", false));

    boolean handled = handler.handle(msg, peer);

    assertTrue(handled);
    verify(replacementStats)
        .shouldRejectRequest(
            argThat(
                context ->
                    context.canAcceptAnyway()
                        && !context.mode().isInsert()
                        && !context.mode().isSSK()
                        && !context.mode().isLocal()
                        && context.mode().isOfferReply()
                        && context.source() == peer
                        && !context.hasInStore()
                        && !context.preferInsert()
                        && !context.mode().realTimeFlag()
                        && context.tag() instanceof OfferReplyTag));
    verify(nodeStats, never()).shouldRejectRequest(any(RequestAdmissionContext.class));
  }

  @Test
  void handle_whenSendAsyncThrowsNotConnected_swallowsException() throws Exception {
    Key key = mock(Key.class);
    byte[] keyBytes = new byte[] {30, 31, 32};
    when(key.getFullKey()).thenReturn(keyBytes);
    byte[] invalidAuthenticator = Arrays.copyOf(authenticatorKey, authenticatorKey.length);
    invalidAuthenticator[0] = (byte) (invalidAuthenticator[0] + 1);
    long uid = 77L;
    Message msg = offeredKeyMessage(key, invalidAuthenticator, uid, false, false);

    when(peer.transport()).thenReturn(transport);
    doThrow(new NotConnectedException("gone"))
        .when(transport)
        .sendAsync(any(Message.class), isNull(), same(failureTable.senderCounter));

    boolean handled = handler.handle(msg, peer);

    assertTrue(handled);
  }

  private Message offeredKeyMessage(
      Key key, byte[] authenticator, long uid, boolean needPubKey, boolean realTimeFlag) {
    Message msg = new Message(DMT.FNPGetOfferedKey);
    msg.set(DMT.KEY, key);
    msg.set(DMT.OFFER_AUTHENTICATOR, new ShortBuffer(authenticator));
    msg.set(DMT.UID, uid);
    msg.set(DMT.NEED_PUB_KEY, needPubKey);
    if (realTimeFlag) {
      msg.addSubMessage(DMT.createFNPRealTimeFlag(true));
    }
    return msg;
  }

  private byte[] validAuthenticatorFor(byte[] keyBytes) {
    return HMAC.macWithSHA256(authenticatorKey, keyBytes);
  }
}
