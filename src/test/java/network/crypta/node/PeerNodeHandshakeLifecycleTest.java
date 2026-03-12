package network.crypta.node;

import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerNodeHandshakeLifecycleTest {

  @Mock private PeerNode peerNode;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerNodeRuntime runtime;

  @Mock private Peer replyTo;

  @Mock private PeerNode.HandshakeState handshakeState;

  @Mock private PacketFormat packetFormat;

  @Mock private NodeCrypto crypto;

  @Test
  void createBackoffStatusChecker_whenReferenceProvided_expectCheckerBoundToSameReference() {
    // Arrange
    WeakReference<PeerNode> ref = new WeakReference<>(peerNode);

    // Act
    Runnable checker = PeerNodeHandshakeLifecycle.createBackoffStatusChecker(ref);

    // Assert
    assertInstanceOf(PeerNodeBackoffStatusChecker.class, checker);
    assertSame(ref, ((PeerNodeBackoffStatusChecker) checker).ref);
  }

  @Test
  void completeHandshake_whenNoderefParsingFails_expectMinusOneAndDisconnected() {
    // Arrange
    PeerNodeHandshakeLifecycle lifecycle = new PeerNodeHandshakeLifecycle(peerNode, node, runtime);
    HandshakeCompletionParams params = newParams(123L);
    params.replyTo = replyTo;

    try (MockedStatic<PeerNodeReferenceSupport> noderefSupport =
        mockStatic(PeerNodeReferenceSupport.class)) {
      noderefSupport
          .when(
              () ->
                  PeerNodeReferenceSupport.compressedNoderefToFieldSet(
                      params.data, 0, params.length))
          .thenThrow(new FSParseException("bad noderef"));

      // Act
      long result = lifecycle.completeHandshake(params);

      // Assert
      assertEquals(-1L, result);
    }

    assertTrue(peerNode.bogusNoderef);
    verify(peerNode).calcNextHandshake(true, true, false);
    verify(peerNode).stopARKFetcher();
    verify(runtime).setConnected(eq(false), anyLong());
    verify(node.network().peers()).disconnected(nullable(PeerNode.class));
    verify(peerNode, never()).changedIP(any(Peer.class));
  }

  @Test
  void completeHandshake_whenCurrentTrackerKeysReplayed_expectMinusOneWithoutStateTransition() {
    // Arrange
    PeerNodeHandshakeLifecycle lifecycle = new PeerNodeHandshakeLifecycle(peerNode, node, runtime);
    HandshakeCompletionParams params = newParams(777L);
    params.replyTo = replyTo;
    params.outgoingKey = new byte[] {1, 2, 3, 4};
    params.incommingKey = new byte[] {5, 6, 7, 8};

    SessionKey existingTracker =
        new SessionKey(
            peerNode,
            new SessionKeyCryptoMaterial(
                null, params.outgoingKey, null, params.incommingKey, null, null, null),
            new NewPacketFormatKeyContext(10, 20),
            42L);
    peerNode.currentTracker = existingTracker;

    try (MockedStatic<PeerNodeReferenceSupport> noderefSupport =
        mockStatic(PeerNodeReferenceSupport.class)) {
      noderefSupport
          .when(
              () ->
                  PeerNodeReferenceSupport.compressedNoderefToFieldSet(
                      params.data, 0, params.length))
          .thenReturn(new SimpleFieldSet(true));

      // Act
      long result = lifecycle.completeHandshake(params);

      // Assert
      assertEquals(-1L, result);
    }

    assertSame(existingTracker, peerNode.currentTracker);
    verify(peerNode).calcNextHandshake(true, true, false);
    verify(peerNode).stopARKFetcher();
    verify(peerNode).changedIP(replyTo);
    verify(runtime, never()).setConnected(anyBoolean(), anyLong());
    verify(node.network().peers(), never()).disconnected(nullable(PeerNode.class));
  }

  @Test
  void completeHandshake_whenParamsHaveWrongType_expectClassCastException() {
    // Arrange
    PeerNodeHandshakeLifecycle lifecycle = new PeerNodeHandshakeLifecycle(peerNode, node, runtime);
    Object invalidParams = new Object();

    // Act + Assert
    assertThrows(ClassCastException.class, () -> lifecycle.completeHandshake(invalidParams));
  }

  @Test
  void completeHandshake_whenVerifiedAndRoutable_expectTrackerPromotionAndConnectCallbacks() {
    // Arrange
    PeerNodeHandshakeLifecycle lifecycle = new PeerNodeHandshakeLifecycle(peerNode, node, runtime);
    HandshakeCompletionParams params = newParams(999L);
    params.replyTo = replyTo;
    params.unverified = false;
    params.thisBootID = 0L;
    params.ourInitialSeqNum = 1001;
    params.theirInitialSeqNum = 2002;
    params.ourInitialMsgID = 3003;
    params.theirInitialMsgID = 4004;

    setPeerNodeField(peerNode, "handshakeCount", new AtomicInteger(7));
    setPeerNodeField(peerNode, "countSelectionsSinceConnected", new AtomicLong(12));
    setPeerNodeField(peerNode, "handshake", handshakeState);
    setPeerNodeField(peerNode, "crypto", crypto);

    when(runtime.packetFormat()).thenReturn(packetFormat);
    when(peerNode.isConnected()).thenReturn(false, true);

    try (MockedStatic<PeerNodeReferenceSupport> noderefSupport =
        mockStatic(PeerNodeReferenceSupport.class)) {
      noderefSupport
          .when(
              () ->
                  PeerNodeReferenceSupport.compressedNoderefToFieldSet(
                      params.data, 0, params.length))
          .thenReturn(new SimpleFieldSet(true));

      // Act
      long trackerId = lifecycle.completeHandshake(params);

      // Assert
      assertEquals(999L, trackerId);
    }

    assertNotNull(peerNode.currentTracker);
    assertEquals(999L, peerNode.currentTracker.trackerID);
    assertTrue(peerNode.isRoutable);
    assertFalse(peerNode.unroutableNewerVersion);
    assertFalse(peerNode.unroutableOlderVersion);
    assertFalse(peerNode.neverConnected);
    assertFalse(peerNode.isRekeying);
    assertEquals(0L, peerNode.totalBytesExchangedWithCurrentTracker);
    assertEquals(0, peerNode.handshakeCount.get());
    assertEquals(0L, peerNode.countSelectionsSinceConnected.get());
    assertTrue(peerNode.timeLastSentPacket > 0L);
    assertTrue(peerNode.timeLastReceivedPacket > 0L);

    verify(peerNode).calcNextHandshake(true, true, false);
    verify(peerNode).stopARKFetcher();
    verify(peerNode).changedIP(replyTo);
    verify(peerNode).maybeClearPeerAddedTimeOnConnect();
    verify(runtime).setConnected(eq(true), anyLong());
    verify(handshakeState).clearKeyAgreementSchemeContext();
    verify(runtime).maybeDisconnected();
    verify(peerNode).setPeerNodeStatus(anyLong());
    verify(node.network().peers()).addConnectedPeer(nullable(PeerNode.class));
    verify(node.network().peers(), never()).disconnected(nullable(PeerNode.class));
    verify(peerNode).maybeOnConnect();
    verify(crypto)
        .maybeBootConnection(nullable(PeerNode.class), nullable(FreenetInetAddress.class));
  }

  private static HandshakeCompletionParams newParams(long trackerID) {
    HandshakeCompletionParams params = new HandshakeCompletionParams();
    params.trackerID = trackerID;
    params.thisBootID = 1L;
    params.data = new byte[] {11, 22, 33};
    params.length = params.data.length;
    params.outgoingKey = new byte[] {9, 9, 9, 9};
    params.incommingKey = new byte[] {8, 8, 8, 8};
    return params;
  }

  @SuppressWarnings("java:S3011")
  private static void setPeerNodeField(PeerNode target, String fieldName, Object value) {
    try {
      Field field = PeerNode.class.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed to set PeerNode field: " + fieldName, e);
    }
  }
}
