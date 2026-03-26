package network.crypta.node;

import java.security.SecureRandom;
import java.util.stream.Stream;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.bootstrap.NodeBootstrap;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeAnnouncementHandlerTest {

  private static final long UID = 1234L;
  private static final long XFER_UID = 9876L;

  @Mock private Node node;
  @Mock private NodeNetworkSubsystem network;
  @Mock private NodeStats stats;
  @Mock private OpennetManager opennetManager;
  @Mock private SeedAnnounceTracker seedTracker;
  @Mock private PeerTransport transport;
  @Mock private PriorityAwareExecutor executor;
  @Mock private NodeBootstrap bootstrap;
  @Mock private Message message;
  @Mock private PeerNode peerNode;
  @Mock private SeedClientPeerNode seedClient;

  private NodeAnnouncementHandler handler;

  @BeforeEach
  void setUp() {
    handler = new NodeAnnouncementHandler(node);
  }

  @Test
  void handle_whenNonAnnounceMessage_expectFalseAndNoInteractions() {
    MessageType otherType = DMT.FNPRejectedOverload;
    when(message.getSpec()).thenReturn(otherType);

    boolean handled = handler.handle(message, peerNode);

    assertFalse(handled);
    verifyNoInteractions(peerNode);
    verifyNoInteractions(network);
  }

  @ParameterizedTest
  @MethodSource("invalidAnnounceCases")
  void handle_whenInvalidAnnounce_expectRejectOverloadAndReturnTrue(
      double target, short htl, int noderefLength, int paddedLength) throws Exception {
    stubNetworkBasics();
    when(peerNode.transport()).thenReturn(transport);
    stubAnnounceMessage(target, htl, noderefLength, paddedLength);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(captor.capture(), isNull(), any());
    assertSame(DMT.FNPRejectedOverload, captor.getValue().getSpec());
    verify(peerNode, never()).completedAnnounce(UID);
    verifyNoInteractions(executor);
  }

  @Test
  void handle_whenAnnouncementsDisabled_expectOpennetDisabledAndSeedTrackerNotified()
      throws Exception {
    stubNetworkBasics();
    stubOpennetWithSeedTracker();
    when(seedClient.transport()).thenReturn(transport);
    stubAnnounceMessage(0.5, (short) 5, 100, 200);
    when(seedClient.canAcceptAnnouncements()).thenReturn(false);

    boolean handled = handler.handle(message, seedClient);

    assertTrue(handled);
    ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(captor.capture(), isNull(), any());
    assertSame(DMT.FNPOpennetDisabled, captor.getValue().getSpec());
    verify(seedTracker).rejectedAnnounce(seedClient);
    verify(seedClient, never()).completedAnnounce(UID);
    verifyNoInteractions(executor);
  }

  @Test
  void handle_whenDecisionOverload_expectRejectedOverloadAndCompletedAnnounce() throws Exception {
    stubNetworkBasics();
    stubOpennetWithoutSeedTracker();
    when(peerNode.transport()).thenReturn(transport);
    stubAnnounceMessage(0.5, (short) 5, 100, 200);
    when(peerNode.canAcceptAnnouncements()).thenReturn(true);
    when(stats.shouldAcceptAnnouncement(UID)).thenReturn(NodeStats.AnnouncementDecision.OVERLOAD);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(captor.capture(), isNull(), any());
    assertSame(DMT.FNPRejectedOverload, captor.getValue().getSpec());
    verify(peerNode).completedAnnounce(UID);
    verify(peerNode, never()).shouldAcceptAnnounce(UID);
    verifyNoInteractions(executor);
  }

  @Test
  void handle_whenDecisionLoop_expectRejectedLoopAndSeedTrackerNotified() throws Exception {
    stubNetworkBasics();
    stubOpennetWithSeedTracker();
    when(seedClient.transport()).thenReturn(transport);
    stubAnnounceMessage(0.5, (short) 5, 100, 200);
    when(seedClient.canAcceptAnnouncements()).thenReturn(true);
    when(stats.shouldAcceptAnnouncement(UID)).thenReturn(NodeStats.AnnouncementDecision.LOOP);

    boolean handled = handler.handle(message, seedClient);

    assertTrue(handled);
    ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(captor.capture(), isNull(), any());
    assertSame(DMT.FNPRejectedLoop, captor.getValue().getSpec());
    verify(seedTracker).rejectedAnnounce(seedClient);
    verify(seedClient).completedAnnounce(UID);
    verifyNoInteractions(executor);
  }

  @Test
  void handle_whenPeerLimitReached_expectRejectedOverloadAndEndAnnouncement() throws Exception {
    stubNetworkBasics();
    stubOpennetWithoutSeedTracker();
    when(peerNode.transport()).thenReturn(transport);
    stubAnnounceMessage(0.5, (short) 5, 100, 200);
    when(peerNode.canAcceptAnnouncements()).thenReturn(true);
    when(stats.shouldAcceptAnnouncement(UID)).thenReturn(NodeStats.AnnouncementDecision.ACCEPT);
    when(peerNode.shouldAcceptAnnounce(UID)).thenReturn(false);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(captor.capture(), isNull(), any());
    assertSame(DMT.FNPRejectedOverload, captor.getValue().getSpec());
    verify(stats).endAnnouncement(UID);
    verify(peerNode).completedAnnounce(UID);
    verifyNoInteractions(executor);
  }

  @Test
  void handle_whenSeedTrackerRejects_expectRejectedOverloadAndEndAnnouncement() throws Exception {
    stubNetworkBasics();
    stubOpennetWithSeedTracker();
    when(seedClient.transport()).thenReturn(transport);
    when(node.bootstrap()).thenReturn(bootstrap);
    stubAnnounceMessage(0.5, (short) 5, 100, 200);
    SecureRandom random = new SecureRandom();
    when(seedClient.canAcceptAnnouncements()).thenReturn(true);
    when(stats.shouldAcceptAnnouncement(UID)).thenReturn(NodeStats.AnnouncementDecision.ACCEPT);
    when(seedClient.shouldAcceptAnnounce(UID)).thenReturn(true);
    when(bootstrap.fastWeakRandom()).thenReturn(random);
    when(seedTracker.acceptAnnounce(seedClient, random)).thenReturn(false);

    boolean handled = handler.handle(message, seedClient);

    assertTrue(handled);
    ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(captor.capture(), isNull(), any());
    assertSame(DMT.FNPRejectedOverload, captor.getValue().getSpec());
    verify(stats).endAnnouncement(UID);
    verify(seedClient).completedAnnounce(UID);
    verifyNoInteractions(executor);
  }

  @Test
  void handle_whenAcceptedSeedClientWithLowHtl_expectNormalizedHtlAndScheduledSender() {
    stubNetworkBasics();
    stubOpennetWithSeedTracker();
    when(network.executor()).thenReturn(executor);
    when(node.bootstrap()).thenReturn(bootstrap);
    stubAnnounceMessage(0.5, (short) 3, 100, 200);
    SecureRandom random = new SecureRandom();
    when(seedClient.canAcceptAnnouncements()).thenReturn(true);
    when(stats.shouldAcceptAnnouncement(UID)).thenReturn(NodeStats.AnnouncementDecision.ACCEPT);
    when(seedClient.shouldAcceptAnnounce(UID)).thenReturn(true);
    when(bootstrap.fastWeakRandom()).thenReturn(random);
    when(seedTracker.acceptAnnounce(seedClient, random)).thenReturn(true);

    boolean handled = handler.handle(message, seedClient);

    assertTrue(handled);
    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
    ArgumentCaptor<String> labelCaptor = ArgumentCaptor.forClass(String.class);
    verify(executor).execute(runnableCaptor.capture(), labelCaptor.capture());
    assertEquals("Announcement sender for " + UID, labelCaptor.getValue());
    Runnable task = runnableCaptor.getValue();
    assertInstanceOf(AnnounceSender.class, task);
    verify(seedClient, never()).completedAnnounce(UID);
  }

  private void stubAnnounceMessage(double target, short htl, int noderefLength, int paddedLength) {
    when(message.getSpec()).thenReturn(DMT.FNPOpennetAnnounceRequest);
    when(message.getLong(DMT.UID)).thenReturn(UID);
    when(message.getDouble(DMT.TARGET_LOCATION)).thenReturn(target);
    when(message.getShort(DMT.HTL)).thenReturn(htl);
    when(message.getLong(DMT.TRANSFER_UID)).thenReturn(XFER_UID);
    when(message.getInt(DMT.NODEREF_LENGTH)).thenReturn(noderefLength);
    when(message.getInt(DMT.PADDED_LENGTH)).thenReturn(paddedLength);
  }

  private static Stream<Arguments> invalidAnnounceCases() {
    return Stream.of(
        Arguments.of(-0.1, (short) 5, 100, 200),
        Arguments.of(1.0, (short) 5, 100, 200),
        Arguments.of(0.5, (short) 0, 100, 200),
        Arguments.of(0.5, (short) -1, 100, 200),
        Arguments.of(0.5, (short) 5, 100, -1),
        Arguments.of(0.5, (short) 5, 100, OpennetManager.MAX_OPENNET_NODEREF_LENGTH + 1),
        Arguments.of(0.5, (short) 5, 201, 200));
  }

  private void stubNetworkBasics() {
    when(node.network()).thenReturn(network);
    when(network.stats()).thenReturn(stats);
    when(node.maxHTL()).thenReturn((short) 10);
  }

  private void stubOpennetWithoutSeedTracker() {
    when(network.opennet()).thenReturn(opennetManager);
  }

  private void stubOpennetWithSeedTracker() {
    stubOpennetWithoutSeedTracker();
    when(opennetManager.getSeedTracker()).thenReturn(seedTracker);
  }
}
