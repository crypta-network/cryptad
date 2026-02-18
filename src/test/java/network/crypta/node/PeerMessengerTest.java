package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerMessengerTest {
  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerManager peerManager;
  @Mock private NodeStats nodeStats;
  @Mock private Ticker ticker;
  @Mock private PeerNode peerNode;
  @Mock private PeerTransport transport;
  @Mock private Message message;
  @Mock private ByteCounter byteCounter;

  @Captor private ArgumentCaptor<AsyncMessageCallback> callbackCaptor;
  @Captor private ArgumentCaptor<Runnable> runnableCaptor;

  private PeerMessenger messenger;

  @BeforeEach
  void setUp() {
    messenger = new PeerMessenger(node, peerManager);
    Mockito.lenient().when(peerNode.transport()).thenReturn(transport);
  }

  @Test
  void getDisconnCounter_whenBytesReported_updatesNodeStats() {
    when(node.network().stats()).thenReturn(nodeStats);
    ByteCounter counter = messenger.getDisconnCounter();

    counter.receivedBytes(10);
    counter.sentBytes(12);
    counter.sentPayload(5);

    verify(nodeStats).disconnBytesReceived(10);
    verify(nodeStats).disconnBytesSent(12);
    verifyNoMoreInteractions(nodeStats);
  }

  @Test
  void disconnectAndRemove_whenCalled_delegatesToDisconnectWithDefaults() {
    PeerMessenger spy = Mockito.spy(new PeerMessenger(node, peerManager));
    doNothing()
        .when(spy)
        .disconnect(peerNode, true, false, true, false, true, Node.MAX_PEER_INACTIVITY);

    spy.disconnectAndRemove(peerNode, true, false, true);

    verify(spy).disconnect(peerNode, true, false, true, false, true, Node.MAX_PEER_INACTIVITY);
  }

  @Test
  void disconnect_whenPeerMissing_noActionTaken() {
    when(peerManager.havePeer(peerNode)).thenReturn(false);

    messenger.disconnect(peerNode, true, true, false, false, true, 1000L);

    verify(peerManager).havePeer(peerNode);
    verify(peerNode, never()).notifyDisconnecting(anyBoolean());
    verifyNoMoreInteractions(peerManager);
  }

  @Test
  void disconnect_whenAlreadyDisconnecting_noFurtherWork() throws Exception {
    when(peerManager.havePeer(peerNode)).thenReturn(true);
    when(peerNode.notifyDisconnecting(true)).thenReturn(true);

    messenger.disconnect(peerNode, true, true, false, true, true, 1000L);

    verify(peerManager).havePeer(peerNode);
    verify(peerNode).notifyDisconnecting(true);
    verify(peerManager, never()).removePeer(peerNode);
    verify(peerManager, never()).writePeersUrgent(anyBoolean());
    verify(transport, never())
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), any());
  }

  @Test
  void disconnect_whenNotConnected_removesPeerIfRequestedAndDisconnecting() throws Exception {
    when(peerManager.havePeer(peerNode)).thenReturn(true);
    when(peerNode.notifyDisconnecting(false)).thenReturn(false);
    when(peerNode.isDisconnecting()).thenReturn(true);
    when(peerNode.isSeed()).thenReturn(false);
    when(peerNode.isOpennet()).thenReturn(true);
    doThrow(new NotConnectedException())
        .when(transport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), any(ByteCounter.class));

    messenger.disconnect(peerNode, true, true, false, false, true, 1000L);

    verify(peerManager).removePeer(peerNode);
    verify(peerManager).writePeersUrgent(true);
    verify(ticker, never()).queueTimedJob(any(Runnable.class), anyLong());
  }

  @Test
  void disconnect_whenWaitForAckFalse_removesOnSentCallback() throws Exception {
    when(peerManager.havePeer(peerNode)).thenReturn(true);
    when(peerNode.notifyDisconnecting(false)).thenReturn(false);
    when(peerNode.isSeed()).thenReturn(false);
    when(peerNode.isOpennet()).thenReturn(false);
    when(node.network().ticker()).thenReturn(ticker);
    when(transport.sendAsync(any(Message.class), callbackCaptor.capture(), any(ByteCounter.class)))
        .thenReturn(null);

    messenger.disconnect(peerNode, true, false, false, false, true, 500L);

    verify(ticker).queueTimedJob(runnableCaptor.capture(), eq(500L));
    callbackCaptor.getValue().sent();

    verify(peerManager).removePeer(peerNode);
    verify(peerManager).writePeersUrgent(false);
  }

  @Test
  void disconnect_whenWaitForAckTrue_removesOnAcknowledged() throws Exception {
    when(peerManager.havePeer(peerNode)).thenReturn(true);
    when(peerNode.notifyDisconnecting(false)).thenReturn(false);
    when(peerNode.isSeed()).thenReturn(false);
    when(peerNode.isOpennet()).thenReturn(true);
    when(node.network().ticker()).thenReturn(ticker);
    when(transport.sendAsync(any(Message.class), callbackCaptor.capture(), any(ByteCounter.class)))
        .thenReturn(null);

    messenger.disconnect(peerNode, true, true, false, false, true, 500L);

    callbackCaptor.getValue().sent();

    verify(peerManager, never()).removePeer(peerNode);
    verify(peerManager, never()).writePeersUrgent(anyBoolean());

    callbackCaptor.getValue().acknowledged();

    verify(peerManager).removePeer(peerNode);
    verify(peerManager).writePeersUrgent(true);
  }

  @Test
  void disconnect_whenSendDisconnectMessageFalse_removesImmediately() throws Exception {
    when(peerManager.havePeer(peerNode)).thenReturn(true);
    when(peerNode.notifyDisconnecting(false)).thenReturn(false);
    when(peerNode.isSeed()).thenReturn(false);
    when(peerNode.isOpennet()).thenReturn(true);

    messenger.disconnect(peerNode, false, true, false, false, true, 1000L);

    verify(peerManager).removePeer(peerNode);
    verify(peerManager).writePeersUrgent(true);
    verify(transport, never())
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), any());
  }

  @Test
  void disconnect_whenTimeoutJobRuns_disconnectsAndRemoves() throws Exception {
    when(peerManager.havePeer(peerNode)).thenReturn(true);
    when(peerNode.notifyDisconnecting(false)).thenReturn(false);
    when(peerNode.isSeed()).thenReturn(false);
    when(peerNode.isOpennet()).thenReturn(false);
    when(peerNode.isDisconnecting()).thenReturn(true);
    when(node.network().ticker()).thenReturn(ticker);
    when(transport.sendAsync(
            any(Message.class), any(AsyncMessageCallback.class), any(ByteCounter.class)))
        .thenReturn(null);

    messenger.disconnect(peerNode, true, true, false, false, true, 250L);

    verify(ticker).queueTimedJob(runnableCaptor.capture(), eq(250L));

    runnableCaptor.getValue().run();

    verify(peerManager).removePeer(peerNode);
    verify(peerManager).writePeersUrgent(false);
    verify(peerNode).disconnected(true, true);
  }

  @Test
  void localBroadcast_whenFilteringByRoutabilityAndVersion_sendsToEligiblePeers() throws Exception {
    PeerNode eligible = Mockito.mock(PeerNode.class);
    PeerNode tooOld = Mockito.mock(PeerNode.class);
    PeerNode notRoutable = Mockito.mock(PeerNode.class);
    PeerTransport eligibleTransport = Mockito.mock(PeerTransport.class);
    PeerTransport tooOldTransport = Mockito.mock(PeerTransport.class);
    PeerTransport notRoutableTransport = Mockito.mock(PeerTransport.class);
    when(eligible.transport()).thenReturn(eligibleTransport);
    Mockito.lenient().when(tooOld.transport()).thenReturn(tooOldTransport);
    Mockito.lenient().when(notRoutable.transport()).thenReturn(notRoutableTransport);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {eligible, tooOld, notRoutable});

    when(eligible.getBuildNumber()).thenReturn(10);
    when(eligible.isRoutable()).thenReturn(true);
    when(eligible.isRealConnection()).thenReturn(true);

    when(tooOld.getBuildNumber()).thenReturn(3);
    when(tooOld.isRoutable()).thenReturn(true);
    when(tooOld.isRealConnection()).thenReturn(true);

    when(notRoutable.getBuildNumber()).thenReturn(12);
    when(notRoutable.isRoutable()).thenReturn(false);

    messenger.localBroadcast(message, false, true, byteCounter, 5, 15);

    verify(eligibleTransport).sendAsync(message, null, byteCounter);
    verify(tooOldTransport, never()).sendAsync(any(Message.class), any(), any());
    verify(notRoutableTransport, never()).sendAsync(any(Message.class), any(), any());
  }

  @Test
  void localBroadcast_whenIgnoreRoutability_sendsOnlyToRealConnectedPeers() throws Exception {
    PeerNode connectedReal = Mockito.mock(PeerNode.class);
    PeerNode connectedNotReal = Mockito.mock(PeerNode.class);
    PeerNode disconnected = Mockito.mock(PeerNode.class);
    PeerTransport connectedRealTransport = Mockito.mock(PeerTransport.class);
    PeerTransport connectedNotRealTransport = Mockito.mock(PeerTransport.class);
    PeerTransport disconnectedTransport = Mockito.mock(PeerTransport.class);
    when(connectedReal.transport()).thenReturn(connectedRealTransport);
    Mockito.lenient().when(connectedNotReal.transport()).thenReturn(connectedNotRealTransport);
    Mockito.lenient().when(disconnected.transport()).thenReturn(disconnectedTransport);
    when(peerManager.myPeers())
        .thenReturn(new PeerNode[] {connectedReal, connectedNotReal, disconnected});

    when(connectedReal.getBuildNumber()).thenReturn(42);
    when(connectedReal.isConnected()).thenReturn(true);
    when(connectedReal.isRealConnection()).thenReturn(true);

    when(connectedNotReal.getBuildNumber()).thenReturn(42);
    when(connectedNotReal.isConnected()).thenReturn(true);
    when(connectedNotReal.isRealConnection()).thenReturn(false);

    when(disconnected.getBuildNumber()).thenReturn(42);
    when(disconnected.isConnected()).thenReturn(false);

    doThrow(new NotConnectedException())
        .when(connectedRealTransport)
        .sendAsync(any(Message.class), any(), any(ByteCounter.class));

    assertDoesNotThrow(() -> messenger.localBroadcast(message, true, true, byteCounter, 0, 100));

    verify(connectedRealTransport).sendAsync(message, null, byteCounter);
    verify(connectedNotRealTransport, never()).sendAsync(any(Message.class), any(), any());
    verify(disconnectedTransport, never()).sendAsync(any(Message.class), any(), any());
  }

  @Test
  void locallyBroadcastDiffNodeRef_whenFlagsSet_targetsMatchingConnectedPeers() {
    PeerNode darknet = Mockito.mock(PeerNode.class);
    PeerNode opennet = Mockito.mock(PeerNode.class);
    PeerNode disconnected = Mockito.mock(PeerNode.class);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {darknet, opennet, disconnected});

    when(darknet.isConnected()).thenReturn(true);
    when(darknet.isDarknet()).thenReturn(true);

    when(opennet.isConnected()).thenReturn(true);
    when(opennet.isDarknet()).thenReturn(false);

    when(disconnected.isConnected()).thenReturn(false);

    SimpleFieldSet fieldSet = new SimpleFieldSet(false);

    messenger.locallyBroadcastDiffNodeRef(fieldSet, true, false);

    verify(darknet)
        .sendNodeToNodeMessage(fieldSet, Node.N2N_MESSAGE_TYPE_DIFFNODEREF, false, 0, false);
    verify(opennet, never())
        .sendNodeToNodeMessage(
            any(SimpleFieldSet.class), anyInt(), anyBoolean(), anyLong(), anyBoolean());
    verify(disconnected, never())
        .sendNodeToNodeMessage(
            any(SimpleFieldSet.class), anyInt(), anyBoolean(), anyLong(), anyBoolean());
  }
}
