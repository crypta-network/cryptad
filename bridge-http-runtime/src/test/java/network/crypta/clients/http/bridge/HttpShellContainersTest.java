package network.crypta.clients.http.bridge;

import java.net.URI;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import network.crypta.clients.http.LegacyAdminHttpRouteRegistrar;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.StartupToadlet;
import network.crypta.config.SubConfig;
import network.crypta.platform.webshell.routes.WebShellPaths;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.runtime.http.HttpShellRuntimeSupport;
import network.crypta.support.HTMLNode;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class HttpShellContainersTest {

  @Test
  void createMethodReference_whenCreateCalled_wrapsSimpleToadletServerAndDelegatesSeamMethods()
      throws Exception {
    SubConfig fproxyConfig = mock(SubConfig.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    StartupToadlet startupToadlet = mock(StartupToadlet.class);
    HttpShellRuntimeSupport runtimeSupport = legacyCompatibleRuntimeSupport();
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    URI uri = URI.create("http://127.0.0.1/filter");
    HTMLNode parentNode = mock(HTMLNode.class);
    HTMLNode formNode = mock(HTMLNode.class);
    AtomicReference<List<?>> constructorArgs = new AtomicReference<>();

    try (MockedConstruction<SimpleToadletServer> construction =
        mockConstruction(
            SimpleToadletServer.class,
            (server, context) -> {
              constructorArgs.set(context.arguments());
              when(server.getStartupToadlet()).thenReturn(startupToadlet);
              when(server.isEnabled()).thenReturn(true);
              when(server.isAdvancedModeEnabled()).thenReturn(true);
              when(server.isFProxyJavascriptEnabled()).thenReturn(false);
              when(server.listenPort()).thenReturn(8888);
              when(server.primaryUiRoot()).thenReturn(WebShellPaths.SHELL_ROOT);
              when(server.isLinkExcepted(uri)).thenReturn(true);
              when(server.addFormChild(parentNode, "/submit", "form")).thenReturn(formNode);
            })) {
      HttpShellContainer container = HttpShellContainers.create(fproxyConfig, executor);

      assertEquals(1, construction.constructed().size());
      SimpleToadletServer server = construction.constructed().getFirst();
      List<?> args = constructorArgs.get();
      assertSame(fproxyConfig, args.get(0));
      assertInstanceOf(network.crypta.support.io.ArrayBucketFactory.class, args.get(1));
      assertSame(executor, args.get(2));

      container.setRuntimeSupport(runtimeSupport);
      container.setBucketFactory(tempBucketFactory);
      Consumer<String> primaryUiRootListener = _ -> {};
      container.setPrimaryUiRootListener(primaryUiRootListener);
      container.markStartupPrngReady();
      container.createFproxy();
      container.finishStart();
      container.removeStartupToadlet();
      container.start();

      assertTrue(container.isEnabled());
      assertTrue(container.isAdvancedModeEnabled());
      assertTrue(container.isLinkExcepted(uri));
      assertFalse(container.isFProxyJavascriptEnabled());
      assertEquals(8888, container.listenPort());
      assertEquals(WebShellPaths.SHELL_ROOT, container.primaryUiRoot());
      assertSame(formNode, container.addFormChild(parentNode, "/submit", "form"));

      verify(server)
          .setRuntimeSupport((network.crypta.clients.http.HttpShellRuntimeSupport) runtimeSupport);
      verify(server).setRouteRegistrar(isA(LegacyAdminHttpRouteRegistrar.class));
      verify(server).setBucketFactory(tempBucketFactory);
      verify(server).setPrimaryUiRootListener(primaryUiRootListener);
      verify(server).createFproxy();
      verify(server).finishStart();
      verify(server).removeStartupToadlet();
      verify(server).start();
      verify(server).addFormChild(parentNode, "/submit", "form");
      verify(startupToadlet).setIsPRNGReady();
    }
  }

  @Test
  void
      simpleToadletServerHttpShellContainer_whenRuntimeMethodsQueried_expectDelegateValuesReturned() {
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    HttpShellContainer container = new SimpleToadletServerHttpShellContainer(server);
    URI uri = URI.create("http://127.0.0.1:8888/test");
    HTMLNode parentNode = mock(HTMLNode.class);
    HTMLNode formNode = mock(HTMLNode.class);

    when(server.isEnabled()).thenReturn(true);
    when(server.addFormChild(parentNode, "/submit", "form")).thenReturn(formNode);
    when(server.isAdvancedModeEnabled()).thenReturn(false);
    when(server.isFProxyJavascriptEnabled()).thenReturn(true);
    when(server.listenPort()).thenReturn(7777);
    when(server.primaryUiRoot()).thenReturn(WebShellPaths.SHELL_ROOT);
    when(server.isLinkExcepted(uri)).thenReturn(true);
    Consumer<String> primaryUiRootListener = _ -> {};

    assertTrue(container.isEnabled());
    assertSame(formNode, container.addFormChild(parentNode, "/submit", "form"));
    assertFalse(container.isAdvancedModeEnabled());
    assertTrue(container.isFProxyJavascriptEnabled());
    assertEquals(7777, container.listenPort());
    assertEquals(WebShellPaths.SHELL_ROOT, container.primaryUiRoot());
    container.setPrimaryUiRootListener(primaryUiRootListener);
    assertTrue(container.isLinkExcepted(uri));

    verify(server).setPrimaryUiRootListener(primaryUiRootListener);
  }

  @Test
  void simpleToadletServerHttpShellContainer_whenRuntimeSupportLacksLegacyBridge_throws() {
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    HttpShellContainer container = new SimpleToadletServerHttpShellContainer(server);
    HttpShellRuntimeSupport runtimeSupport = mock(HttpShellRuntimeSupport.class);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class, () -> container.setRuntimeSupport(runtimeSupport));

    assertEquals(
        "SimpleToadletServerHttpShellContainer requires runtimeSupport to also implement "
            + "network.crypta.clients.http.HttpShellRuntimeSupport; pair custom "
            + "HttpShellRuntimeSupportFactory bindings with a compatible "
            + "HttpShellContainerFactory",
        exception.getMessage());
    verifyNoInteractions(server);
  }

  private static HttpShellRuntimeSupport legacyCompatibleRuntimeSupport() {
    return (HttpShellRuntimeSupport)
        mock(
            network.crypta.clients.http.HttpShellRuntimeSupport.class,
            withSettings().extraInterfaces(HttpShellRuntimeSupport.class));
  }
}
