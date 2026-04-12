package network.crypta.clients.http;

import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.platform.apphost.AppHost;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings("java:S100")
class HttpShellBrowseBootstrapTest {

  @Test
  void create_whenGivenBrowseRoot_returnsBootstrapWithSameCollaborators() {
    BookmarkManager bookmarkManager = mock(BookmarkManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar =
        mock(LegacyHttpBrowseRouteRegistrar.class);

    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(
            bookmarkManager, client, appHost, browseRoot, browseRouteRegistrar);

    assertSame(bookmarkManager, bootstrap.bookmarkManager());
    assertSame(client, bootstrap.client());
    assertSame(appHost, bootstrap.appHost());
    assertSame(browseRoot, bootstrap.browseRoot());
    assertSame(browseRouteRegistrar, bootstrap.browseRouteRegistrar());
  }

  @Test
  void create_whenGivenInitializationHook_returnsBootstrapWithSameCollaborators() {
    BookmarkManager bookmarkManager = mock(BookmarkManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar =
        mock(LegacyHttpBrowseRouteRegistrar.class);
    AtomicReference<RuntimePorts> runtimePortsSeen = new AtomicReference<>();

    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(
            bookmarkManager,
            client,
            appHost,
            browseRoot,
            browseRouteRegistrar,
            runtimePortsSeen::set);

    assertSame(bookmarkManager, bootstrap.bookmarkManager());
    assertSame(client, bootstrap.client());
    assertSame(appHost, bootstrap.appHost());
    assertSame(browseRoot, bootstrap.browseRoot());
    assertSame(browseRouteRegistrar, bootstrap.browseRouteRegistrar());

    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    bootstrap.initializeSharedShellState(runtimePorts);

    assertSame(runtimePorts, runtimePortsSeen.get());
  }

  @Test
  void create_whenInitializationHookNull_throwsNullPointerException() {
    BookmarkManager bookmarkManager = mock(BookmarkManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar =
        mock(LegacyHttpBrowseRouteRegistrar.class);

    assertThrows(
        NullPointerException.class,
        () ->
            HttpShellBrowseBootstrap.create(
                bookmarkManager, client, appHost, browseRoot, browseRouteRegistrar, null));
  }

  @Test
  void create_whenBrowseRouteRegistrarNull_throwsNullPointerException() {
    BookmarkManager bookmarkManager = mock(BookmarkManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);

    assertThrows(
        NullPointerException.class,
        () -> HttpShellBrowseBootstrap.create(bookmarkManager, client, appHost, browseRoot, null));
  }

  @Test
  void initializeSharedShellState_whenUsingDefaultHook_skipsInitialization() {
    BookmarkManager bookmarkManager = mock(BookmarkManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    AppHost appHost = mock(AppHost.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar =
        mock(LegacyHttpBrowseRouteRegistrar.class);
    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(
            bookmarkManager, client, appHost, mock(Toadlet.class), browseRouteRegistrar);

    bootstrap.initializeSharedShellState(runtimePorts);

    verifyNoInteractions(runtimePorts);
  }

  @Test
  void initializeSharedShellState_whenRuntimePortsNull_throwsNullPointerException() {
    BookmarkManager bookmarkManager = mock(BookmarkManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar =
        mock(LegacyHttpBrowseRouteRegistrar.class);
    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(
            bookmarkManager, client, appHost, browseRoot, browseRouteRegistrar);

    assertThrows(NullPointerException.class, () -> bootstrap.initializeSharedShellState(null));
  }
}
