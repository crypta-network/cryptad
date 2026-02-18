package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerNodeRuntimeTest {

  @Mock private PeerNode peerNode;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  private PeerNodeRuntime runtime;

  @BeforeEach
  void setUp() {
    runtime = new PeerNodeRuntime(peerNode, node, null);
  }

  @Test
  void createBackoffStatusChecker_whenReferenceProvided_expectCheckerBoundToSameReference() {
    // Arrange
    WeakReference<PeerNode> ref = new WeakReference<>(peerNode);

    // Act
    Runnable checker = PeerNodeRuntime.createBackoffStatusChecker(ref);

    // Assert
    assertInstanceOf(PeerNodeBackoffStatusChecker.class, checker);
    assertSame(ref, ((PeerNodeBackoffStatusChecker) checker).ref);
  }

  @Test
  void verifyReferenceSignature_whenVerifierThrows_expectWrappedFsParseException()
      throws Exception {
    // Arrange
    PeerNodeReferenceSupport referenceSupport = mock(PeerNodeReferenceSupport.class);
    setField(runtime, PeerNodeRuntime.class, "referenceSupport", referenceSupport);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    RuntimeException cause = new RuntimeException("invalid");
    doThrow(cause).when(referenceSupport).verifyReferenceSignature(fs);

    // Act
    FSParseException thrown =
        assertThrows(FSParseException.class, () -> runtime.verifyReferenceSignature(fs));

    // Assert
    assertEquals("Invalid signature", thrown.getMessage());
    assertSame(cause, thrown.getCause());
  }

  @Test
  void maybeSendPacket_whenPacketFormatMissing_expectFalse() {
    // Arrange + Act
    boolean sent = runtime.maybeSendPacket(123L, false);

    // Assert
    assertFalse(sent);
  }

  @Test
  void maybeSendPacket_whenPacketFormatSends_expectTrue() throws Exception {
    // Arrange
    PacketFormat packetFormat = mock(PacketFormat.class);
    runtime.setPacketFormat(packetFormat);
    when(packetFormat.maybeSendPacket(777L, true)).thenReturn(true);

    // Act
    boolean sent = runtime.maybeSendPacket(777L, true);

    // Assert
    assertTrue(sent);
    verify(packetFormat).maybeSendPacket(777L, true);
  }

  @Test
  void maybeSendPacket_whenPacketFormatBlocked_expectDisconnectAndFalse() throws Exception {
    // Arrange
    PacketFormat packetFormat = mock(PacketFormat.class);
    runtime.setPacketFormat(packetFormat);
    when(packetFormat.maybeSendPacket(17L, false)).thenThrow(new BlockedTooLongException(500L));

    // Act
    boolean sent = runtime.maybeSendPacket(17L, false);

    // Assert
    assertFalse(sent);
    verify(peerNode).forceDisconnect();
  }

  @Test
  void maxPeerPingTime_whenRuntimeNodeMissing_expectFallbackDefault() {
    // Arrange
    setField(runtime, PeerNodeRuntime.class, "node", null);

    // Act
    long result = runtime.maxPeerPingTime();

    // Assert
    assertEquals(NodeStats.DEFAULT_MAX_PING_TIME * 2L, result);
  }

  @Test
  void maxPeerPingTime_whenNodeStatsMissing_expectFallbackDefault() {
    // Arrange
    when(node.network().stats()).thenReturn(null);

    // Act
    long result = runtime.maxPeerPingTime();

    // Assert
    assertEquals(NodeStats.DEFAULT_MAX_PING_TIME * 2L, result);
  }

  @Test
  void maxPeerPingTime_whenNodeStatsPresent_expectDelegatedValue() {
    // Arrange
    NodeStats stats = mock(NodeStats.class);
    when(node.network().stats()).thenReturn(stats);
    when(stats.maxPeerPingTime()).thenReturn(4242L);

    // Act
    long result = runtime.maxPeerPingTime();

    // Assert
    assertEquals(4242L, result);
  }

  @Test
  void isLowCapacity_whenNoIncomingLoadStats_expectFalse() {
    // Arrange
    PeerNodeLoadTracker loadTracker = mock(PeerNodeLoadTracker.class);
    setField(runtime, PeerNodeRuntime.class, "loadTracker", loadTracker);
    when(loadTracker.getLastIncomingLoadStats(true)).thenReturn(null);

    // Act
    boolean lowCapacity = runtime.isLowCapacity(true);

    // Assert
    assertFalse(lowCapacity);
  }

  @Test
  void isLowCapacity_whenInputThresholdAbovePeerLimit_expectTrue() {
    // Arrange
    PeerNodeLoadTracker loadTracker = mock(PeerNodeLoadTracker.class);
    setField(runtime, PeerNodeRuntime.class, "loadTracker", loadTracker);
    PeerLoadStats peerLoadStats = mock(PeerLoadStats.class);
    when(loadTracker.getLastIncomingLoadStats(true)).thenReturn(peerLoadStats);
    when(peerLoadStats.peerLimit(true)).thenReturn(100.0);

    NodeStats stats = mock(NodeStats.class);
    NodePinger nodePinger = mock(NodePinger.class);
    setField(stats, NodeStats.class, "nodePinger", nodePinger);
    when(node.network().stats()).thenReturn(stats);
    when(nodePinger.capacityThreshold(true, true)).thenReturn(100.0001);

    // Act
    boolean lowCapacity = runtime.isLowCapacity(true);

    // Assert
    assertTrue(lowCapacity);
    verify(nodePinger, never()).capacityThreshold(true, false);
  }

  @Test
  void isLowCapacity_whenThresholdsWithinPeerLimits_expectFalse() {
    // Arrange
    PeerNodeLoadTracker loadTracker = mock(PeerNodeLoadTracker.class);
    setField(runtime, PeerNodeRuntime.class, "loadTracker", loadTracker);
    PeerLoadStats peerLoadStats = mock(PeerLoadStats.class);
    when(loadTracker.getLastIncomingLoadStats(false)).thenReturn(peerLoadStats);
    when(peerLoadStats.peerLimit(true)).thenReturn(100.0);
    when(peerLoadStats.peerLimit(false)).thenReturn(100.0);

    NodeStats stats = mock(NodeStats.class);
    NodePinger nodePinger = mock(NodePinger.class);
    setField(stats, NodeStats.class, "nodePinger", nodePinger);
    when(node.network().stats()).thenReturn(stats);
    when(nodePinger.capacityThreshold(false, true)).thenReturn(90.0);
    when(nodePinger.capacityThreshold(false, false)).thenReturn(80.0);

    // Act
    boolean lowCapacity = runtime.isLowCapacity(false);

    // Assert
    assertFalse(lowCapacity);
  }

  @Test
  void
      parseLocationAndMaybePeerCounts_whenUnknownLocationBecomesValid_expectChangedAndMarkUpdate() {
    // Arrange
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(PeerNode.SFS_KEY_LOCATION, "0.25");
    boolean[] shouldUpdatePeerCounts = new boolean[] {false};

    // Act
    boolean changed = runtime.parseLocationAndMaybePeerCounts(fs, shouldUpdatePeerCounts);

    // Assert
    assertTrue(changed);
    assertTrue(shouldUpdatePeerCounts[0]);
    assertEquals(0.25, runtime.getLocation(), 1.0e-12);
  }

  @Test
  void parseLocationAndMaybePeerCounts_whenLocationInvalid_expectNoChange() {
    // Arrange
    runtime.setLocation(0.4);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(PeerNode.SFS_KEY_LOCATION, "invalid-location");
    boolean[] shouldUpdatePeerCounts = new boolean[] {false};

    // Act
    boolean changed = runtime.parseLocationAndMaybePeerCounts(fs, shouldUpdatePeerCounts);

    // Assert
    assertFalse(changed);
    assertFalse(shouldUpdatePeerCounts[0]);
    assertEquals(0.4, runtime.getLocation(), 1.0e-12);
  }

  @Test
  void completeHandshake_whenLifecycleReturnsTrackerId_expectDelegation() {
    // Arrange
    PeerNodeHandshakeLifecycle handshakeLifecycle = mock(PeerNodeHandshakeLifecycle.class);
    setField(runtime, PeerNodeRuntime.class, "handshakeLifecycle", handshakeLifecycle);
    Object params = new Object();
    when(handshakeLifecycle.completeHandshake(params)).thenReturn(77L);

    // Act
    long trackerId = runtime.completeHandshake(params);

    // Assert
    assertEquals(77L, trackerId);
    verify(handshakeLifecycle).completeHandshake(params);
  }

  @Test
  void notifyOpennetOnDisconnect_whenManagerExists_expectOnDisconnectCalled() {
    // Arrange
    Node localNode = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    OpennetManager opennet = mock(OpennetManager.class);
    when(localNode.network().opennet()).thenReturn(opennet);

    // Act
    runtime.notifyOpennetOnDisconnect(localNode);

    // Assert
    verify(opennet).onDisconnect();
  }

  @Test
  void notifyOpennetOnConnect_whenManagerExists_expectOnConnectedPeerCalled() {
    // Arrange
    Node localNode = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    OpennetManager opennet = mock(OpennetManager.class);
    when(localNode.network().opennet()).thenReturn(opennet);

    // Act
    runtime.notifyOpennetOnConnect(localNode, peerNode);

    // Assert
    verify(opennet).onConnectedPeer(peerNode);
  }

  @Test
  void notifyOpennetHelpers_whenManagerMissing_expectNoThrow() {
    // Arrange
    Node localNode = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(localNode.network().opennet()).thenReturn(null);

    // Act + Assert
    assertDoesNotThrow(() -> runtime.notifyOpennetOnDisconnect(localNode));
    assertDoesNotThrow(() -> runtime.notifyOpennetOnConnect(localNode, peerNode));
  }

  @SuppressWarnings("java:S3011")
  private static void setField(
      Object target, Class<?> declaringClass, String fieldName, Object value) {
    try {
      Field field = declaringClass.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed to set field " + fieldName + " on " + declaringClass, e);
    }
  }
}
