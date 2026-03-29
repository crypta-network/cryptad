package network.crypta.runtime.endpoints.http;

import java.io.File;
import java.net.InetAddress;
import java.net.URI;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.clients.http.FProxyFetchInProgress.REFILTER_POLICY;
import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.clients.http.PageMaker.THEME;
import network.crypta.clients.http.PageMaker;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.StartupToadlet;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletRegistration;
import network.crypta.config.SubConfig;
import network.crypta.support.HTMLNode;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class HttpShellContainersTest {

  @Test
  void create_whenCalled_wrapsSimpleToadletServerAndDelegatesSeamMethods() throws Exception {
    SubConfig fproxyConfig = mock(SubConfig.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    StartupToadlet startupToadlet = mock(StartupToadlet.class);
    HttpShellRuntimeSupport runtimeSupport = mock(HttpShellRuntimeSupport.class);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    URI uri = URI.create("http://127.0.0.1/filter");
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
              when(server.isLinkExcepted(uri)).thenReturn(true);
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
      container.markStartupPrngReady();
      container.createFproxy();
      container.finishStart();
      container.removeStartupToadlet();
      container.start();

      assertTrue(container.isEnabled());
      assertTrue(container.isAdvancedModeEnabled());
      assertTrue(container.isLinkExcepted(uri));
      assertFalse(container.isFProxyJavascriptEnabled());

      verify(server).setRuntimeSupport(runtimeSupport);
      verify(server).setBucketFactory(tempBucketFactory);
      verify(server).createFproxy();
      verify(server).finishStart();
      verify(server).removeStartupToadlet();
      verify(server).start();
      verify(startupToadlet).setIsPRNGReady();
    }
  }

  @Test
  void
      simpleToadletServerHttpShellContainer_whenReadOnlyDelegationsQueried_expectDelegateValuesReturned()
          throws Exception {
    // Arrange
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    HttpShellContainer container = new SimpleToadletServerHttpShellContainer(server);
    URI uri = URI.create("http://127.0.0.1:8888/test");
    InetAddress remoteAddress = InetAddress.getLoopbackAddress();
    Toadlet toadlet = mock(Toadlet.class);
    HTMLNode parentNode = mock(HTMLNode.class);
    HTMLNode formNode = mock(HTMLNode.class);
    BucketFactory bucketFactory = mock(BucketFactory.class);
    PageMaker pageMaker = mock(PageMaker.class);
    THEME theme = THEME.CRYPTAFORGE;
    REFILTER_POLICY reFilterPolicy = REFILTER_POLICY.ACCEPT_OLD;
    File overrideFile = new File("override.css");

    when(server.findToadlet(uri)).thenReturn(toadlet);
    when(server.getTheme()).thenReturn(theme);
    when(server.getFormPassword()).thenReturn("form-password");
    when(server.isAllowedFullAccess(remoteAddress)).thenReturn(true);
    when(server.doRobots()).thenReturn(false);
    when(server.addFormChild(parentNode, "/submit", "form")).thenReturn(formNode);
    when(server.enablePersistentConnections()).thenReturn(true);
    when(server.enableInlinePrefetch()).thenReturn(false);
    when(server.enableExtendedMethodHandling()).thenReturn(true);
    when(server.enableCachingForChkAndSskKeys()).thenReturn(false);
    when(server.getBucketFactory()).thenReturn(bucketFactory);
    when(server.allowPosts()).thenReturn(true);
    when(server.publicGatewayMode()).thenReturn(false);
    when(server.enableActivelinks()).thenReturn(true);
    when(server.sendAllThemes()).thenReturn(false);
    when(server.isFProxyWebPushingEnabled()).thenReturn(true);
    when(server.disableProgressPage()).thenReturn(false);
    when(server.getPageMaker()).thenReturn(pageMaker);
    when(server.fproxyHasCompletedWizard()).thenReturn(true);
    when(server.getReFilterPolicy()).thenReturn(reFilterPolicy);
    when(server.getOverrideFile()).thenReturn(overrideFile);
    when(server.getURL()).thenReturn("http://127.0.0.1:8888/");
    when(server.getURL("example.test")).thenReturn("http://example.test:8888/");
    when(server.isSSL()).thenReturn(true);
    when(server.generateUniqueID()).thenReturn(1234L);

    // Act + Assert
    assertSame(toadlet, container.findToadlet(uri));
    assertSame(theme, container.getTheme());
    assertEquals("form-password", container.getFormPassword());
    assertTrue(container.isAllowedFullAccess(remoteAddress));
    assertFalse(container.doRobots());
    assertSame(formNode, container.addFormChild(parentNode, "/submit", "form"));
    assertTrue(container.enablePersistentConnections());
    assertFalse(container.enableInlinePrefetch());
    assertTrue(container.enableExtendedMethodHandling());
    assertFalse(container.enableCachingForChkAndSskKeys());
    assertSame(bucketFactory, container.getBucketFactory());
    assertTrue(container.allowPosts());
    assertFalse(container.publicGatewayMode());
    assertTrue(container.enableActivelinks());
    assertFalse(container.sendAllThemes());
    assertTrue(container.isFProxyWebPushingEnabled());
    assertFalse(container.disableProgressPage());
    assertSame(pageMaker, container.getPageMaker());
    assertTrue(container.fproxyHasCompletedWizard());
    assertSame(reFilterPolicy, container.getReFilterPolicy());
    assertSame(overrideFile, container.getOverrideFile());
    assertEquals("http://127.0.0.1:8888/", container.getURL());
    assertEquals("http://example.test:8888/", container.getURL("example.test"));
    assertTrue(container.isSSL());
    assertEquals(1234L, container.generateUniqueID());
  }

  @Test
  void simpleToadletServerHttpShellContainer_whenMutationMethodsInvoked_expectDelegateCalled() {
    // Arrange
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    HttpShellContainer container = new SimpleToadletServerHttpShellContainer(server);
    Toadlet toadlet = mock(Toadlet.class);
    ToadletRegistration registration = mock(ToadletRegistration.class);

    // Act
    container.register(toadlet, registration);
    container.unregister(toadlet);
    container.setAdvancedMode(true);

    // Assert
    verify(server).register(toadlet, registration);
    verify(server).unregister(toadlet);
    verify(server).setAdvancedMode(true);
  }
}
