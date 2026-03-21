package network.crypta.clients.fcp;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PeerNode;
import network.crypta.node.RequestStarter;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Type;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.useralerts.UserAlertManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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
  @Mock private UserAlertManager alerts;
  @Mock private Node node;
  @Mock private NodeNetworkSubsystem network;
  @Mock private PeerNode peerNode;
  @Mock private FCPConnectionHandler handler;

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
  void watchFeeds_whenEnabledTrue_watchesHandler() {
    when(core.getAlerts()).thenReturn(alerts);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    support.watchFeeds(handler, true);

    verify(alerts).watch(handler);
  }

  @Test
  void watchFeeds_whenEnabledFalse_unwatchesHandler() {
    when(core.getAlerts()).thenReturn(alerts);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    support.watchFeeds(handler, false);

    verify(alerts).unwatch(handler);
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
