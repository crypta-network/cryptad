package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Arrays;
import network.crypta.crypt.HMAC;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerNodeOfferSupportTest {

  @Test
  void offer_whenConnected_sendsMessageWithAuthenticator() throws NotConnectedException {
    PeerNode peer = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);

    Node node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    FailureTable failureTable = org.mockito.Mockito.mock(FailureTable.class);
    byte[] offerAuthenticatorKey = new byte[32];
    for (int i = 0; i < offerAuthenticatorKey.length; i++) {
      offerAuthenticatorKey[i] = (byte) i;
    }
    setField(failureTable, "offerAuthenticatorKey", offerAuthenticatorKey);

    NodeStats nodeStats = org.mockito.Mockito.mock(NodeStats.class);
    ByteCounter sendOffersCtr = org.mockito.Mockito.mock(ByteCounter.class);
    setField(nodeStats, "sendOffersCtr", sendOffersCtr);

    when(node.routing().failureTable()).thenReturn(failureTable);
    when(node.network().stats()).thenReturn(nodeStats);
    setField(peer, "node", node);

    byte[] routingKey = new byte[NodeCHK.KEY_LENGTH];
    Arrays.fill(routingKey, (byte) 0x5A);
    Key key = new NodeCHK(routingKey, Key.ALGO_AES_CTR_256_SHA256);

    PeerNodeOfferSupport support = new PeerNodeOfferSupport(peer);

    support.offer(key);

    ArgumentCaptor<Message> msgCaptor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(msgCaptor.capture(), isNull(), same(sendOffersCtr));

    Message sent = msgCaptor.getValue();
    assertSame(DMT.FNPOfferKey, sent.getSpec());
    assertSame(key, sent.getObject(DMT.KEY));
    byte[] expectedAuthenticator = HMAC.macWithSHA256(offerAuthenticatorKey, key.getFullKey());
    assertArrayEquals(expectedAuthenticator, sent.getShortBufferBytes(DMT.OFFER_AUTHENTICATOR));
  }

  @Test
  void offer_whenTransportThrowsNotConnectedException_expectNoThrow() throws Exception {
    PeerNode peer = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);

    Node node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    FailureTable failureTable = org.mockito.Mockito.mock(FailureTable.class);
    setField(failureTable, "offerAuthenticatorKey", new byte[32]);

    NodeStats nodeStats = org.mockito.Mockito.mock(NodeStats.class);
    ByteCounter sendOffersCtr = org.mockito.Mockito.mock(ByteCounter.class);
    setField(nodeStats, "sendOffersCtr", sendOffersCtr);

    when(node.routing().failureTable()).thenReturn(failureTable);
    when(node.network().stats()).thenReturn(nodeStats);
    setField(peer, "node", node);

    doThrow(new NotConnectedException())
        .when(transport)
        .sendAsync(org.mockito.ArgumentMatchers.any(Message.class), isNull(), same(sendOffersCtr));

    byte[] routingKey = new byte[NodeCHK.KEY_LENGTH];
    Key key = new NodeCHK(routingKey, Key.ALGO_AES_PCFB_256_SHA256);
    PeerNodeOfferSupport support = new PeerNodeOfferSupport(peer);

    assertDoesNotThrow(() -> support.offer(key));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void offer_whenKeyNull_expectNullPointerException() {
    PeerNode peer = org.mockito.Mockito.mock(PeerNode.class);
    Node node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    setField(peer, "node", node);

    PeerNodeOfferSupport support = new PeerNodeOfferSupport(peer);

    assertThrows(NullPointerException.class, () -> support.offer(null));
  }

  @SuppressWarnings("java:S3011")
  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field field = findField(target.getClass(), fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Failed to set field: " + fieldName, e);
    }
  }

  private static Field findField(Class<?> type, String fieldName) throws NoSuchFieldException {
    Class<?> current = type;
    while (current != null) {
      try {
        return current.getDeclaredField(fieldName);
      } catch (NoSuchFieldException _) {
        current = current.getSuperclass();
      }
    }
    throw new NoSuchFieldException(fieldName);
  }
}
