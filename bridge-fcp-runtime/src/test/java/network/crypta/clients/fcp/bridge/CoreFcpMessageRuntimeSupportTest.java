package network.crypta.clients.fcp.bridge;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URL;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.ContentFilterCallbacks;
import network.crypta.client.filter.ContentFilterRequest;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.client.filter.UnsafeContentTypeException;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.clients.fcp.FcpDarknetPeerHandle;
import network.crypta.clients.fcp.FcpFilterResult;
import network.crypta.clients.fcp.FcpPeerLookupResult;
import network.crypta.clients.fcp.FcpPeerReferenceFetchException;
import network.crypta.clients.fcp.FcpProbeError;
import network.crypta.clients.fcp.FcpProbeListener;
import network.crypta.clients.fcp.FcpProbeType;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PeerNode;
import network.crypta.node.probe.Error;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Type;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.alerts.feed.UserAlertFeedSubscriber;
import network.crypta.runtime.peers.reference.PeerReferenceTextLoader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CoreFcpMessageRuntimeSupportTest {

  @Mock private NodeClientCore core;
  @Mock private Node node;
  @Mock private NodeNetworkSubsystem network;
  @Mock private DarknetPeerNode darknetPeerNode;
  @Mock private PeerNode peerNode;
  @Mock private FCPConnectionHandler handler;
  @Mock private LinkFilterExceptionProvider linkFilterExceptionProvider;

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
  void readPeerReferenceFromUrl_whenCalled_delegatesToPeerReferenceTextLoader() throws Exception {
    URL url = URI.create("https://example.invalid/peer.txt").toURL();
    StringBuilder reference = referenceText("identity=peer-url\n");
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);

    try (MockedStatic<PeerReferenceTextLoader> mockedLoader =
        org.mockito.Mockito.mockStatic(PeerReferenceTextLoader.class)) {
      mockedLoader.when(() -> PeerReferenceTextLoader.readFromUrl(url)).thenReturn(reference);

      StringBuilder actual = support.readPeerReferenceFromUrl(url);

      assertSame(reference, actual);
      mockedLoader.verify(() -> PeerReferenceTextLoader.readFromUrl(url));
    }
  }

  @Test
  void readPeerReferenceFromCryptaUri_whenCalled_delegatesToCoreClientAndLoader() throws Exception {
    FreenetURI uri = new FreenetURI("KSK@test");
    StringBuilder reference = referenceText("identity=peer-uri\n");
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);

    when(core.makeClient((short) 2, true, true)).thenReturn(client);
    try (MockedStatic<PeerReferenceTextLoader> mockedLoader =
        org.mockito.Mockito.mockStatic(PeerReferenceTextLoader.class)) {
      mockedLoader
          .when(() -> PeerReferenceTextLoader.readFromFreenetUri(uri, client))
          .thenReturn(reference);

      StringBuilder actual = support.readPeerReferenceFromCryptaUri(uri, (short) 2, true, true);

      assertSame(reference, actual);
      verify(core).makeClient((short) 2, true, true);
      mockedLoader.verify(() -> PeerReferenceTextLoader.readFromFreenetUri(uri, client));
    }
  }

  @Test
  void readPeerReferenceFromCryptaUri_whenFetchFails_wrapsFetchFailure() throws Exception {
    FreenetURI uri = new FreenetURI("KSK@test");
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    FetchException fetchException = new FetchException(FetchExceptionMode.INTERNAL_ERROR);

    when(core.makeClient((short) 2, true, true)).thenReturn(client);
    try (MockedStatic<PeerReferenceTextLoader> mockedLoader =
        org.mockito.Mockito.mockStatic(PeerReferenceTextLoader.class)) {
      mockedLoader
          .when(() -> PeerReferenceTextLoader.readFromFreenetUri(uri, client))
          .thenThrow(fetchException);

      FcpPeerReferenceFetchException actual =
          assertThrows(
              FcpPeerReferenceFetchException.class,
              () -> support.readPeerReferenceFromCryptaUri(uri, (short) 2, true, true));

      assertSame(fetchException, actual.getCause());
      verify(core).makeClient((short) 2, true, true);
      mockedLoader.verify(() -> PeerReferenceTextLoader.readFromFreenetUri(uri, client));
    }
  }

  @Test
  void readPeerReferenceFromCryptaUri_whenReadFailsWithIo_propagatesIoException() throws Exception {
    FreenetURI uri = new FreenetURI("KSK@test");
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    IOException ioException = new IOException("bucket read failed");

    when(core.makeClient((short) 2, true, true)).thenReturn(client);
    try (MockedStatic<PeerReferenceTextLoader> mockedLoader =
        org.mockito.Mockito.mockStatic(PeerReferenceTextLoader.class)) {
      mockedLoader
          .when(() -> PeerReferenceTextLoader.readFromFreenetUri(uri, client))
          .thenThrow(ioException);

      IOException actual =
          assertThrows(
              IOException.class,
              () -> support.readPeerReferenceFromCryptaUri(uri, (short) 2, true, true));

      assertSame(ioException, actual);
      verify(core).makeClient((short) 2, true, true);
      mockedLoader.verify(() -> PeerReferenceTextLoader.readFromFreenetUri(uri, client));
    }
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
  void filterContent_whenCalled_delegatesToContentFilterAndWrapsResult() throws Exception {
    byte[] payload = "payload".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    InputStream input = new ByteArrayInputStream(payload);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    ClientContext clientContext = clientContextWith(linkFilterExceptionProvider);
    when(core.getClientContext()).thenReturn(clientContext);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);
    URI fakeUri = URI.create("http://127.0.0.1:8888/");

    try (MockedStatic<ContentFilter> staticFilter =
        org.mockito.Mockito.mockStatic(ContentFilter.class)) {
      staticFilter
          .when(
              () ->
                  ContentFilter.filter(
                      any(ContentFilterRequest.class), any(ContentFilterCallbacks.class)))
          .thenAnswer(
              invocation -> {
                ContentFilterRequest request = invocation.getArgument(0);
                //noinspection resource
                request.output().write(request.input().readAllBytes());
                ContentFilterCallbacks callbacks = invocation.getArgument(1);
                assertEquals(fakeUri, callbacks.baseURI());
                assertSame(linkFilterExceptionProvider, callbacks.linkFilterExceptionProvider());
                return filterStatusUtf8Text();
              });

      FcpFilterResult actual = support.filterContent(input, output, "text/plain", fakeUri);

      assertEquals("UTF-8", actual.charset());
      assertEquals("text/plain", actual.mimeType());
      assertFalse(actual.unsafeContentType());
    }

    assertEquals("payload", output.toString(java.nio.charset.StandardCharsets.UTF_8));
  }

  @Test
  void filterContent_whenRuntimeRejectsUnsafe_returnsUnsafeResult() throws Exception {
    InputStream input = new ByteArrayInputStream(new byte[] {1, 2, 3});
    OutputStream output = new ByteArrayOutputStream();
    ClientContext clientContext = clientContextWith(linkFilterExceptionProvider);
    when(core.getClientContext()).thenReturn(clientContext);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);
    UnsafeContentTypeException unsafe =
        new UnsafeContentTypeException() {
          @Override
          public String getMessage() {
            return "unsafe";
          }

          @Override
          public String getHTMLEncodedTitle() {
            return "unsafe";
          }

          @Override
          public String getRawTitle() {
            return "unsafe";
          }
        };

    try (MockedStatic<ContentFilter> staticFilter =
        org.mockito.Mockito.mockStatic(ContentFilter.class)) {
      staticFilter
          .when(
              () ->
                  ContentFilter.filter(
                      any(ContentFilterRequest.class), any(ContentFilterCallbacks.class)))
          .thenThrow(unsafe);

      FcpFilterResult actual =
          support.filterContent(input, output, "text/plain", URI.create("http://127.0.0.1:8888/"));

      assertTrue(actual.unsafeContentType());
      assertNull(actual.charset());
      assertNull(actual.mimeType());
    }
  }

  @Test
  void filterContent_whenFilterThrowsIo_propagatesIOException() throws Exception {
    InputStream input = new ByteArrayInputStream(new byte[] {1, 2, 3});
    OutputStream output = new ByteArrayOutputStream();
    ClientContext clientContext = clientContextWith(linkFilterExceptionProvider);
    when(core.getClientContext()).thenReturn(clientContext);
    CoreFcpMessageRuntimeSupport support = new CoreFcpMessageRuntimeSupport(core);
    IOException ioException = new IOException("filter failed");

    try (MockedStatic<ContentFilter> staticFilter =
        org.mockito.Mockito.mockStatic(ContentFilter.class)) {
      staticFilter
          .when(
              () ->
                  ContentFilter.filter(
                      any(ContentFilterRequest.class), any(ContentFilterCallbacks.class)))
          .thenThrow(ioException);

      IOException actual =
          assertThrows(
              IOException.class,
              () ->
                  support.filterContent(
                      input, output, "text/plain", URI.create("http://127.0.0.1:8888/")));

      assertSame(ioException, actual);
    }
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

  private static StringBuilder referenceText(String text) {
    return new StringBuilder().append(text);
  }

  private static ClientContext clientContextWith(LinkFilterExceptionProvider provider)
      throws ReflectiveOperationException {
    ClientContext context = mock(ClientContext.class);
    Field field = ClientContext.class.getField("linkFilterExceptionProvider");
    field.setAccessible(true);
    field.set(context, provider);
    return context;
  }

  @SuppressWarnings("java:S3011")
  private static ContentFilter.FilterStatus filterStatusUtf8Text() {
    try {
      java.lang.reflect.Constructor<ContentFilter.FilterStatus> constructor =
          ContentFilter.FilterStatus.class.getDeclaredConstructor(String.class, String.class);
      constructor.setAccessible(true);
      return constructor.newInstance("UTF-8", "text/plain");
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Unable to construct FilterStatus", e);
    }
  }
}
