package network.crypta.clients.fcp.bridge;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.clients.fcp.FcpDarknetPeerHandle;
import network.crypta.clients.fcp.FcpPeerLookupResult;
import network.crypta.clients.fcp.FcpProbeError;
import network.crypta.clients.fcp.FcpProbeListener;
import network.crypta.clients.fcp.FcpProbeType;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PeerNode;
import network.crypta.node.RequestStarter;
import network.crypta.node.probe.Error;
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
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CoreFcpMessageRuntimeSupportTest {

  @Mock private NodeClientCore core;
  @Mock private HighLevelSimpleClient client;
  @Mock private Node node;
  @Mock private NodeNetworkSubsystem network;
  @Mock private DarknetPeerNode darknetPeerNode;
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
  void findPeer_whenPeerUnknown_returnsUnknownResult() {
    when(core.getNode()).thenReturn(node);
    when(node.network()).thenReturn(network);
    when(network.getPeerNode("peer-1")).thenReturn(null);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    FcpPeerLookupResult actual = support.findPeer("peer-1");

    assertEquals(FcpPeerLookupResult.Kind.UNKNOWN, actual.kind());
  }

  @Test
  void findPeer_whenPeerIsNotDarknet_returnsNonDarknetResult() {
    when(core.getNode()).thenReturn(node);
    when(node.network()).thenReturn(network);
    when(network.getPeerNode("peer-1")).thenReturn(peerNode);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    FcpPeerLookupResult actual = support.findPeer("peer-1");

    assertEquals(FcpPeerLookupResult.Kind.NON_DARKNET, actual.kind());
  }

  @Test
  void findPeer_whenPeerIsDarknet_returnsDarknetHandleResult() throws Exception {
    when(core.getNode()).thenReturn(node);
    when(node.network()).thenReturn(network);
    when(network.getPeerNode("peer-1")).thenReturn(darknetPeerNode);
    when(darknetPeerNode.sendTextFeed("hello")).thenReturn(17);
    FreenetURI uri = new FreenetURI("KSK@test");
    when(darknetPeerNode.sendDownloadFeed(uri, "description")).thenReturn(23);
    when(darknetPeerNode.sendBookmarkFeed(uri, "bookmark", "description", true)).thenReturn(31);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    FcpPeerLookupResult actual = support.findPeer("peer-1");
    FcpDarknetPeerHandle handle = actual.requireDarknetPeerHandle();

    assertEquals(FcpPeerLookupResult.Kind.DARKNET, actual.kind());
    assertEquals(17, handle.sendTextFeed("hello"));
    assertEquals(23, handle.sendDownloadFeed(uri, "description"));
    assertEquals(31, handle.sendBookmarkFeed(uri, "bookmark", "description", true));
    verify(darknetPeerNode).sendTextFeed("hello");
    verify(darknetPeerNode).sendDownloadFeed(uri, "description");
    verify(darknetPeerNode).sendBookmarkFeed(uri, "bookmark", "description", true);
  }

  @Test
  void startProbe_whenCalled_mapsEveryProbeTypeToRuntimeType() {
    when(core.getNode()).thenReturn(node);
    when(node.network()).thenReturn(network);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);
    FcpProbeListener listener = org.mockito.Mockito.mock(FcpProbeListener.class);

    for (FcpProbeType probeType : FcpProbeType.values()) {
      ArgumentCaptor<Type> typeCaptor = ArgumentCaptor.forClass(Type.class);
      ArgumentCaptor<Listener> listenerCaptor = ArgumentCaptor.forClass(Listener.class);

      support.startProbe((byte) 5, 42L, probeType, listener);

      verify(network)
          .startProbe(eq((byte) 5), eq(42L), typeCaptor.capture(), listenerCaptor.capture());
      assertEquals(expectedRuntimeType(probeType), typeCaptor.getValue());
      assertNotNull(listenerCaptor.getValue());
      clearInvocations(network);
    }
  }

  @Test
  void startProbe_whenRuntimeCallbacksArrive_forwardsThemToAdapterListener() {
    when(core.getNode()).thenReturn(node);
    when(node.network()).thenReturn(network);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);
    FcpProbeListener listener = org.mockito.Mockito.mock(FcpProbeListener.class);
    ArgumentCaptor<Listener> listenerCaptor = ArgumentCaptor.forClass(Listener.class);
    float[] linkLengths = new float[] {1.5f, 2.5f};
    byte[] rejectStats = new byte[] {3, 4, 5};

    support.startProbe((byte) 5, 42L, FcpProbeType.BUILD, listener);

    verify(network).startProbe(eq((byte) 5), eq(42L), eq(Type.BUILD), listenerCaptor.capture());
    Listener runtimeListener = listenerCaptor.getValue();
    assertNotNull(runtimeListener);

    runtimeListener.onError(Error.DISCONNECTED, (byte) 1, true);
    runtimeListener.onError(Error.OVERLOAD, (byte) 2, false);
    runtimeListener.onError(Error.TIMEOUT, (byte) 3, true);
    runtimeListener.onError(Error.UNKNOWN, (byte) 4, false);
    runtimeListener.onError(Error.UNRECOGNIZED_TYPE, (byte) 5, true);
    runtimeListener.onError(Error.CANNOT_FORWARD, (byte) 6, false);
    runtimeListener.onRefused();
    runtimeListener.onOutputBandwidth(7.5f);
    runtimeListener.onBuild(8);
    runtimeListener.onIdentifier(9L, (byte) 10);
    runtimeListener.onLinkLengths(linkLengths);
    runtimeListener.onLocation(11.5f);
    runtimeListener.onStoreSize(12.5f);
    runtimeListener.onUptime(13.5f);
    runtimeListener.onRejectStats(rejectStats);
    runtimeListener.onOverallBulkOutputCapacity((byte) 14, 15.5f);

    verify(listener).onError(FcpProbeError.DISCONNECTED, (byte) 1, true);
    verify(listener).onError(FcpProbeError.OVERLOAD, (byte) 2, false);
    verify(listener).onError(FcpProbeError.TIMEOUT, (byte) 3, true);
    verify(listener).onError(FcpProbeError.UNKNOWN, (byte) 4, false);
    verify(listener).onError(FcpProbeError.UNRECOGNIZED_TYPE, (byte) 5, true);
    verify(listener).onError(FcpProbeError.CANNOT_FORWARD, (byte) 6, false);
    verify(listener).onRefused();
    verify(listener).onOutputBandwidth(7.5f);
    verify(listener).onBuild(8);
    verify(listener).onIdentifier(9L, (byte) 10);
    verify(listener).onLinkLengths(linkLengths);
    verify(listener).onLocation(11.5f);
    verify(listener).onStoreSize(12.5f);
    verify(listener).onUptime(13.5f);
    verify(listener).onRejectStats(rejectStats);
    verify(listener).onOverallBulkOutputCapacity((byte) 14, 15.5f);
  }

  @Test
  void startProbe_whenListenerNull_throwsNullPointerException() {
    when(core.getNode()).thenReturn(node);
    when(node.network()).thenReturn(network);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    assertThrows(
        NullPointerException.class,
        () -> support.startProbe((byte) 5, 42L, FcpProbeType.BUILD, null));
  }

  private static Type expectedRuntimeType(FcpProbeType probeType) {
    return switch (probeType) {
      case BANDWIDTH -> Type.BANDWIDTH;
      case BUILD -> Type.BUILD;
      case IDENTIFIER -> Type.IDENTIFIER;
      case LINK_LENGTHS -> Type.LINK_LENGTHS;
      case LOCATION -> Type.LOCATION;
      case STORE_SIZE -> Type.STORE_SIZE;
      case UPTIME_48H -> Type.UPTIME_48H;
      case UPTIME_7D -> Type.UPTIME_7D;
      case REJECT_STATS -> Type.REJECT_STATS;
      case OVERALL_BULK_OUTPUT_CAPACITY_USAGE -> Type.OVERALL_BULK_OUTPUT_CAPACITY_USAGE;
    };
  }
}
