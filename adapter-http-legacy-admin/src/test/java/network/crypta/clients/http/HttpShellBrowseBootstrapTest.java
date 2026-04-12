package network.crypta.clients.http;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.platform.apphost.AppHost;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class HttpShellBrowseBootstrapTest {

  @Test
  void create_whenGivenBrowseRoot_returnsBootstrapWithSameCollaborators() {
    BookmarkManager bookmarkManager = mock(BookmarkManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);

    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(bookmarkManager, client, appHost, browseRoot);

    assertSame(bookmarkManager, bootstrap.bookmarkManager());
    assertSame(client, bootstrap.client());
    assertSame(appHost, bootstrap.appHost());
    assertSame(browseRoot, bootstrap.browseRoot());
  }

  @Test
  void create_whenGivenFproxyCollaborators_returnsBootstrapWithConstructedFproxyToadlet() {
    BookmarkManager bookmarkManager = mock(BookmarkManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    AppHost appHost = mock(AppHost.class);
    FProxyRuntimeSupport runtimeSupport = mock(FProxyRuntimeSupport.class);
    FProxyFetchTracker fetchTracker = mock(FProxyFetchTracker.class);
    when(runtimeSupport.clientContext()).thenReturn(mock(ClientContext.class));

    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(
            bookmarkManager, client, appHost, runtimeSupport, fetchTracker);

    assertSame(bookmarkManager, bootstrap.bookmarkManager());
    assertSame(client, bootstrap.client());
    assertSame(appHost, bootstrap.appHost());
    assertInstanceOf(FProxyToadlet.class, bootstrap.browseRoot());
  }

  @Test
  void initializeSharedShellState_whenBrowseRootIsFproxy_seedsForceLinkRandom() {
    BookmarkManager bookmarkManager = mock(BookmarkManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    AppHost appHost = mock(AppHost.class);
    FProxyRuntimeSupport runtimeSupport = mock(FProxyRuntimeSupport.class);
    FProxyFetchTracker fetchTracker = mock(FProxyFetchTracker.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    RandomnessPort randomnessPort = mock(RandomnessPort.class);
    when(runtimeSupport.clientContext()).thenReturn(mock(ClientContext.class));
    when(runtimePorts.randomness()).thenReturn(randomnessPort);
    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(
            bookmarkManager, client, appHost, runtimeSupport, fetchTracker);

    byte[] previousRandom = FProxyToadlet.random;
    try {
      FProxyToadlet.random = null;

      bootstrap.initializeSharedShellState(runtimePorts);

      ArgumentCaptor<byte[]> randomCaptor = ArgumentCaptor.forClass(byte[].class);
      verify(runtimePorts).randomness();
      verify(randomnessPort).fillSecureRandom(randomCaptor.capture());
      assertSame(randomCaptor.getValue(), FProxyToadlet.random);
      assertEquals(32, randomCaptor.getValue().length);
    } finally {
      FProxyToadlet.random = previousRandom;
    }
  }

  @Test
  void initializeSharedShellState_whenBrowseRootIsNotFproxy_skipsRandomInitialization() {
    BookmarkManager bookmarkManager = mock(BookmarkManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(bookmarkManager, client, appHost, browseRoot);

    bootstrap.initializeSharedShellState(runtimePorts);

    verifyNoInteractions(runtimePorts);
  }

  @Test
  void initializeSharedShellState_whenRuntimePortsNull_throwsNullPointerException() {
    BookmarkManager bookmarkManager = mock(BookmarkManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);
    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(bookmarkManager, client, appHost, browseRoot);

    assertThrows(NullPointerException.class, () -> bootstrap.initializeSharedShellState(null));
  }
}
