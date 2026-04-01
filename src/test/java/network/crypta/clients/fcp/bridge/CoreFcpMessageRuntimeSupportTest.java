package network.crypta.clients.fcp.bridge;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PeerNode;
import network.crypta.node.RequestStarter;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Type;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.alerts.feed.UserAlertFeedSubscriber;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CoreFcpMessageRuntimeSupportTest {

  @Mock private NodeClientCore core;
  @Mock private HighLevelSimpleClient client;
  @Mock private Node node;
  @Mock private NodeNetworkSubsystem network;
  @Mock private PeerNode peerNode;
  @Mock private FCPConnectionHandler handler;

  private static final class RecordingAlerts extends UserAlertManager {
    private FcpUserAlertFeedSubscriber watched;
    private FcpUserAlertFeedSubscriber unwatched;

    private RecordingAlerts() {
      super(org.mockito.Mockito.mock(NodeClientCore.class));
    }

    @Override
    public void watch(UserAlertFeedSubscriber subscriber) {
      watched = (FcpUserAlertFeedSubscriber) subscriber;
    }

    @Override
    public void unwatch(UserAlertFeedSubscriber subscriber) {
      unwatched = (FcpUserAlertFeedSubscriber) subscriber;
    }
  }

  @Test
  void constructor_whenCoreNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new CoreFcpMessageRuntimeSupport(null));
  }

  @Test
  void makeClient_whenCalled_delegatesToCore() {
    when(core.makeClient(RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, true, true))
        .thenReturn(client);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    HighLevelSimpleClient actual =
        support.makeClient(RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, true, true);

    assertSame(client, actual);
    verify(core).makeClient(RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, true, true);
  }

  @Test
  void watchFeeds_whenEnabledTrue_wrapsHandlerInFeedSubscriber() {
    RecordingAlerts recordingAlerts = new RecordingAlerts();
    when(core.getAlerts()).thenReturn(recordingAlerts);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    support.watchFeeds(handler, true);

    assertNotNull(recordingAlerts.watched);
    assertSame(handler, recordingAlerts.watched.handler());
  }

  @Test
  void watchFeeds_whenEnabledFalse_wrapsHandlerInFeedSubscriber() {
    RecordingAlerts recordingAlerts = new RecordingAlerts();
    when(core.getAlerts()).thenReturn(recordingAlerts);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    support.watchFeeds(handler, false);

    assertNotNull(recordingAlerts.unwatched);
    assertSame(handler, recordingAlerts.unwatched.handler());
  }

  @Test
  void watchFeeds_whenSameHandlerToggled_expectStableSubscriberEquality() {
    RecordingAlerts recordingAlerts = new RecordingAlerts();
    when(core.getAlerts()).thenReturn(recordingAlerts);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    support.watchFeeds(handler, true);
    support.watchFeeds(handler, false);

    assertNotNull(recordingAlerts.watched);
    assertNotNull(recordingAlerts.unwatched);
    assertEquals(recordingAlerts.watched, recordingAlerts.unwatched);
  }

  @Test
  void shutdownNode_whenCalled_exitsNode() {
    when(core.getNode()).thenReturn(node);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    support.shutdownNode("Received FCP shutdown message");

    verify(node).exit("Received FCP shutdown message");
  }

  @Test
  void findPeer_whenCalled_returnsPeerNode() {
    when(core.getNode()).thenReturn(node);
    when(node.network()).thenReturn(network);
    when(network.getPeerNode("peer-1")).thenReturn(peerNode);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    PeerNode actual = support.findPeer("peer-1");

    assertSame(peerNode, actual);
  }

  @Test
  void startProbe_whenCalled_delegatesToNetwork() {
    when(core.getNode()).thenReturn(node);
    when(node.network()).thenReturn(network);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);
    Listener listener = org.mockito.Mockito.mock(Listener.class);
    ArgumentCaptor<Listener> listenerCaptor = ArgumentCaptor.forClass(Listener.class);

    support.startProbe((byte) 5, 42L, Type.BUILD, listener);

    verify(network).startProbe(eq((byte) 5), eq(42L), eq(Type.BUILD), listenerCaptor.capture());
    assertNotNull(listenerCaptor.getValue());
    assertSame(listener, listenerCaptor.getValue());
  }
}
