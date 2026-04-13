package network.crypta.clients.http;

import java.util.concurrent.atomic.AtomicReference;
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
    BookmarkManagerHandle bookmarkManager = mock(BookmarkManagerHandle.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar =
        mock(LegacyHttpBrowseRouteRegistrar.class);

    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(bookmarkManager, appHost, browseRoot, browseRouteRegistrar);

    assertSame(bookmarkManager, bootstrap.bookmarkManager());
    assertSame(appHost, bootstrap.appHost());
    assertSame(browseRoot, bootstrap.browseRoot());
    assertSame(browseRouteRegistrar, bootstrap.browseRouteRegistrar());
  }

  @Test
  void create_whenGivenInitializationHook_returnsBootstrapWithSameCollaborators() {
    BookmarkManagerHandle bookmarkManager = mock(BookmarkManagerHandle.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar =
        mock(LegacyHttpBrowseRouteRegistrar.class);
    AtomicReference<RuntimePorts> runtimePortsSeen = new AtomicReference<>();

    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(
            bookmarkManager, appHost, browseRoot, browseRouteRegistrar, runtimePortsSeen::set);

    assertSame(bookmarkManager, bootstrap.bookmarkManager());
    assertSame(appHost, bootstrap.appHost());
    assertSame(browseRoot, bootstrap.browseRoot());
    assertSame(browseRouteRegistrar, bootstrap.browseRouteRegistrar());

    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    bootstrap.initializeSharedShellState(runtimePorts);

    assertSame(runtimePorts, runtimePortsSeen.get());
  }

  @Test
  void create_whenInitializationHookNull_throwsNullPointerException() {
    BookmarkManagerHandle bookmarkManager = mock(BookmarkManagerHandle.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar =
        mock(LegacyHttpBrowseRouteRegistrar.class);

    assertThrows(
        NullPointerException.class,
        () ->
            HttpShellBrowseBootstrap.create(
                bookmarkManager, appHost, browseRoot, browseRouteRegistrar, null));
  }

  @Test
  void create_whenBrowseRouteRegistrarNull_throwsNullPointerException() {
    BookmarkManagerHandle bookmarkManager = mock(BookmarkManagerHandle.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);

    assertThrows(
        NullPointerException.class,
        () -> HttpShellBrowseBootstrap.create(bookmarkManager, appHost, browseRoot, null));
  }

  @Test
  void initializeSharedShellState_whenUsingDefaultHook_skipsInitialization() {
    BookmarkManagerHandle bookmarkManager = mock(BookmarkManagerHandle.class);
    AppHost appHost = mock(AppHost.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar =
        mock(LegacyHttpBrowseRouteRegistrar.class);
    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(
            bookmarkManager, appHost, mock(Toadlet.class), browseRouteRegistrar);

    bootstrap.initializeSharedShellState(runtimePorts);

    verifyNoInteractions(runtimePorts);
  }

  @Test
  void initializeSharedShellState_whenRuntimePortsNull_throwsNullPointerException() {
    BookmarkManagerHandle bookmarkManager = mock(BookmarkManagerHandle.class);
    AppHost appHost = mock(AppHost.class);
    Toadlet browseRoot = mock(Toadlet.class);
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar =
        mock(LegacyHttpBrowseRouteRegistrar.class);
    HttpShellBrowseBootstrap bootstrap =
        HttpShellBrowseBootstrap.create(bookmarkManager, appHost, browseRoot, browseRouteRegistrar);

    assertThrows(NullPointerException.class, () -> bootstrap.initializeSharedShellState(null));
  }
}
