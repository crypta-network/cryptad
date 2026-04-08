package network.crypta.clients.http;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.URI;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.clients.http.bridge.CoreHttpShellRuntimeSupport;
import network.crypta.clients.http.bridge.bookmark.CoreBookmarkRuntimeSupport;
import network.crypta.config.Config;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.fs.readiness.LauncherReadinessInfo;
import network.crypta.io.NetworkInterface;
import network.crypta.io.SSLNetworkInterface;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.webshell.routes.WebShellPaths;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.HTMLNode;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.ArrayBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SimpleToadletServerTest {

  @Test
  void findToadlet_whenRegisteredPrefixMatches_returnsRegisteredToadlet() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    DummyToadlet toadlet = new DummyToadlet("/test/");

    server.register(toadlet, ToadletRegistration.basic(null, "/test/", true, false));

    Toadlet result = server.findToadlet(new URI("http://localhost/test/resource"));

    assertSame(toadlet, result);
  }

  @Test
  void findToadlet_whenMissingTrailingSlash_redirectsToNormalizedPrefix() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    DummyToadlet toadlet = new DummyToadlet("/redirect/");
    server.register(toadlet, ToadletRegistration.basic(null, "/redirect/", true, false));

    PermanentRedirectException ex =
        assertThrows(
            PermanentRedirectException.class,
            () -> server.findToadlet(new URI("http://localhost/redirect")));

    assertEquals("/redirect/", ex.newuri.getPath());
  }

  @Test
  void findToadlet_whenShellAliasRequestedWithCatchAllRegistered_redirectsToShellRoot()
      throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    DummyToadlet catchAllToadlet = new DummyToadlet("/");
    DummyToadlet shellToadlet = new DummyToadlet(WebShellPaths.SHELL_ROOT);
    server.register(catchAllToadlet, ToadletRegistration.basic(null, "/", false, false));
    server.register(
        shellToadlet, ToadletRegistration.basic(null, WebShellPaths.SHELL_ROOT, true, false));

    PermanentRedirectException ex =
        assertThrows(
            PermanentRedirectException.class,
            () -> server.findToadlet(new URI("http://localhost/app/node")));

    assertEquals(WebShellPaths.SHELL_ROOT, ex.newuri.getPath());
  }

  @Test
  void findToadlet_whenWizardIncomplete_redirectsToWizardAndPreservesQuery() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    HttpShellRuntimeSupport runtimeSupport = mock(HttpShellRuntimeSupport.class);
    when(runtimeSupport.canRedirectToWizard()).thenReturn(true);
    server.setRuntimeSupport(runtimeSupport);

    PermanentRedirectException ex =
        assertThrows(
            PermanentRedirectException.class,
            () -> server.findToadlet(new URI("http://localhost/hidden?step=1")));

    assertEquals(FirstTimeWizardToadlet.TOADLET_URL, ex.newuri.getPath());
    assertEquals("step=1", ex.newuri.getQuery());
  }

  @Test
  void primaryUiRoot_whenWizardIncomplete_returnsLegacyRoot() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();

    assertEquals("/", server.primaryUiRoot());
  }

  @Test
  void primaryUiRoot_whenWizardComplete_returnsWebShellRoot() throws Exception {
    Config rootConfig = new Config();
    SubConfig config = rootConfig.createSubConfig("fproxy");
    SimpleToadletServer server = newServerWithDefaults(config);
    config.set("hasCompletedWizard", true);

    assertEquals(WebShellPaths.SHELL_ROOT, server.primaryUiRoot());
  }

  @Test
  @SuppressWarnings({"resource", "MustBeClosedChecker"})
  void setPrimaryUiRootListener_whenWizardCompletesAfterStartup_notifiesShellRoot()
      throws Exception {
    Config rootConfig = new Config();
    SubConfig config = rootConfig.createSubConfig("fproxy");
    BucketFactory bucketFactory = mock(BucketFactory.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    SimpleToadletServer server;

    try (MockedStatic<NetworkInterface> netMock = mockStatic(NetworkInterface.class);
        MockedStatic<SSLNetworkInterface> sslMock = mockStatic(SSLNetworkInterface.class)) {
      NetworkInterface iface = mock(NetworkInterface.class);
      netMock
          .when(() -> NetworkInterface.create(anyInt(), any(), any(), any(), anyBoolean()))
          .thenReturn(iface);
      sslMock
          .when(() -> SSLNetworkInterface.createSsl(anyInt(), any(), any(), any(), anyBoolean()))
          .thenReturn(iface);
      server = new SimpleToadletServer(config, bucketFactory, executor);
    }

    AtomicReference<String> notifiedUiRoot = new AtomicReference<>();
    server.setRuntimeSupport(mock(HttpShellRuntimeSupport.class));
    server.setPrimaryUiRootListener(notifiedUiRoot::set);
    server.finishStart();

    config.finishedInitialization();
    config.set("hasCompletedWizard", true);

    assertEquals(WebShellPaths.SHELL_ROOT, server.primaryUiRoot());
    assertEquals(WebShellPaths.SHELL_ROOT, notifiedUiRoot.get());
  }

  @Test
  void notifyPrimaryUiRootChangedIfStarted_whenFinishStartPublishesStateBeforeUnlock_notifiesRoot()
      throws Exception {
    Config rootConfig = new Config();
    SubConfig config = rootConfig.createSubConfig("fproxy");
    SimpleToadletServer server = newServerWithDefaults(config);
    Method notifyMethod =
        SimpleToadletServer.class.getDeclaredMethod(
            "notifyPrimaryUiRootChangedIfStarted", String.class);
    notifyMethod.setAccessible(true);
    AtomicReference<String> notifiedUiRoot = new AtomicReference<>();
    AtomicReference<Throwable> notifierFailure = new AtomicReference<>();
    CountDownLatch invocationReady = new CountDownLatch(1);
    CountDownLatch invocationStarted = new CountDownLatch(1);

    server.setRuntimeSupport(mock(HttpShellRuntimeSupport.class));
    server.setPrimaryUiRootListener(notifiedUiRoot::set);

    Thread notifierThread =
        Thread.ofPlatform()
            .name("simple-toadlet-server-ui-root-notifier")
            .unstarted(
                () -> {
                  try {
                    invocationReady.countDown();
                    assertTrue(invocationStarted.await(5, TimeUnit.SECONDS));
                    notifyMethod.invoke(server, LauncherReadinessInfo.DEFAULT_UI_ROOT);
                  } catch (Throwable t) {
                    notifierFailure.set(t);
                  }
                });
    notifierThread.start();
    assertTrue(invocationReady.await(5, TimeUnit.SECONDS));

    synchronized (server) {
      config.set("hasCompletedWizard", true);
      invocationStarted.countDown();
      server.finishStart();
    }

    notifierThread.join(TimeUnit.SECONDS.toMillis(5));

    assertFalse(notifierThread.isAlive());
    assertEquals(WebShellPaths.SHELL_ROOT, notifiedUiRoot.get());
    assertNull(notifierFailure.get());
  }

  @Test
  void createFproxy_whenInvoked_buildsDaemonDependenciesAndDelegatesOnce() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    PersistentConfig nodeConfig = new PersistentConfig(new SimpleFieldSet(true));
    Ticker ticker = mock(Ticker.class);
    ClientContext clientContext = mock(ClientContext.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    RandomnessPort randomnessPort = mock(RandomnessPort.class);
    NodeClientCore core = mock(NodeClientCore.class, Answers.RETURNS_DEEP_STUBS);
    AppHost appHost = mock(AppHost.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    when(core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true)).thenReturn(client);
    when(core.getClientContext()).thenReturn(clientContext);
    when(core.getRuntimePorts()).thenReturn(runtimePorts);
    when(core.getAlerts()).thenReturn(alerts);
    when(core.getNode().getConfig()).thenReturn(nodeConfig);
    when(core.getNode().network().ticker()).thenReturn(ticker);
    when(runtimePorts.randomness()).thenReturn(randomnessPort);
    when(client.getFetchContext()).thenReturn(fetchContext);
    server.setRuntimeSupport(new CoreHttpShellRuntimeSupport(core, appHost));

    AtomicInteger registrarCalls = new AtomicInteger();
    AtomicReference<FProxyRegistrarDependencies> dependenciesRef = new AtomicReference<>();
    AtomicReference<List<Object>> bookmarkManagerCtorArgs = new AtomicReference<>();
    try (MockedConstruction<BookmarkManager> bookmarkManagers =
            mockConstruction(
                BookmarkManager.class,
                (_, context) -> bookmarkManagerCtorArgs.set(List.copyOf(context.arguments())));
        MockedStatic<FProxyRegistrar> registrarMock = mockStatic(FProxyRegistrar.class)) {
      registrarMock
          .when(
              () ->
                  FProxyRegistrar.maybeCreateFProxyEtc(
                      any(FProxyRegistrarDependencies.class), same(server)))
          .thenAnswer(
              invocation -> {
                registrarCalls.incrementAndGet();
                dependenciesRef.set(invocation.getArgument(0));
                return null;
              });

      server.createFproxy();
      server.createFproxy();

      assertEquals(1, bookmarkManagers.constructed().size());
      assertInstanceOf(CoreBookmarkRuntimeSupport.class, bookmarkManagerCtorArgs.get().get(0));
      assertSame(alerts, bookmarkManagerCtorArgs.get().get(1));
      assertEquals(server.publicGatewayMode(), bookmarkManagerCtorArgs.get().get(2));
    }

    ArgumentCaptor<byte[]> randomCaptor = ArgumentCaptor.forClass(byte[].class);
    verify(runtimePorts, times(1)).randomness();
    verify(randomnessPort, times(1)).fillSecureRandom(randomCaptor.capture());
    assertSame(FProxyToadlet.random, randomCaptor.getValue());
    assertEquals(32, randomCaptor.getValue().length);
    verify(core, times(1)).makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true);
    verify(core, times(1)).getAlerts();
    verify(core, never()).getRandom();
    assertEquals(1, registrarCalls.get());
    assertSame(client, dependenciesRef.get().client());
    assertSame(runtimePorts, dependenciesRef.get().runtimePorts());
    assertSame(appHost, dependenciesRef.get().appHost());
    assertSame(nodeConfig, dependenciesRef.get().config());
    assertInstanceOf(FProxyToadlet.class, dependenciesRef.get().fproxy());
  }

  @Test
  void isLinkExcepted_whenToadletDeclaresException_usesToadletDecision() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    ExceptedToadlet toadlet = new ExceptedToadlet("/except/");
    server.register(toadlet, ToadletRegistration.basic(null, "/except/", true, false));

    boolean result = server.isLinkExcepted(new URI("http://localhost/except/page"));

    assertTrue(result);
  }

  @Test
  void isLinkExcepted_whenNoExceptedToadlet_returnsFalse() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();

    boolean result = server.isLinkExcepted(new URI("http://localhost/nowhere"));

    assertFalse(result);
  }

  @Test
  void finishStart_whenThreatLevelsChange_updatesRefilterPolicyAndPanicVisibility()
      throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    HttpShellRuntimeSupport runtimeSupport = mock(HttpShellRuntimeSupport.class);
    AtomicReference<
            HttpShellRuntimeSupport.ThreatLevelListener<HttpShellRuntimeSupport.NetworkThreatLevel>>
        networkListener = new AtomicReference<>();
    AtomicReference<
            HttpShellRuntimeSupport.ThreatLevelListener<
                HttpShellRuntimeSupport.PhysicalThreatLevel>>
        physicalListener = new AtomicReference<>();
    doAnswer(
            invocation -> {
              networkListener.set(invocation.getArgument(0));
              return null;
            })
        .when(runtimeSupport)
        .addNetworkThreatLevelListener(any());
    doAnswer(
            invocation -> {
              physicalListener.set(invocation.getArgument(0));
              return null;
            })
        .when(runtimeSupport)
        .addPhysicalThreatLevelListener(any());
    server.setRuntimeSupport(runtimeSupport);
    boolean originalPanicButtonState = SimpleToadletServer.isPanicButtonToBeShown;
    try {
      setPanicButtonToBeShown(true);

      server.finishStart();

      assertNotNull(networkListener.get());
      assertNotNull(physicalListener.get());

      networkListener
          .get()
          .onChange(
              HttpShellRuntimeSupport.NetworkThreatLevel.NORMAL,
              HttpShellRuntimeSupport.NetworkThreatLevel.LOW);
      assertEquals(FProxyFetchInProgress.REFILTER_POLICY.ACCEPT_OLD, server.getReFilterPolicy());

      networkListener
          .get()
          .onChange(
              HttpShellRuntimeSupport.NetworkThreatLevel.LOW,
              HttpShellRuntimeSupport.NetworkThreatLevel.NORMAL);
      assertEquals(FProxyFetchInProgress.REFILTER_POLICY.RE_FILTER, server.getReFilterPolicy());

      physicalListener
          .get()
          .onChange(
              HttpShellRuntimeSupport.PhysicalThreatLevel.NORMAL,
              HttpShellRuntimeSupport.PhysicalThreatLevel.LOW);
      assertFalse(SimpleToadletServer.isPanicButtonToBeShown);

      physicalListener
          .get()
          .onChange(
              HttpShellRuntimeSupport.PhysicalThreatLevel.LOW,
              HttpShellRuntimeSupport.PhysicalThreatLevel.NORMAL);
      assertTrue(SimpleToadletServer.isPanicButtonToBeShown);
    } finally {
      setPanicButtonToBeShown(originalPanicButtonState);
    }
  }

  private static void setPanicButtonToBeShown(boolean shown) {
    SimpleToadletServer.isPanicButtonToBeShown = shown;
  }

  @Test
  void addFormChild_whenRuntimeSupportProvidesPassword_includesHiddenInput() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    HttpShellRuntimeSupport runtimeSupport = mock(HttpShellRuntimeSupport.class);
    when(runtimeSupport.formPassword()).thenReturn("secret-token");
    server.setRuntimeSupport(runtimeSupport);

    HTMLNode parent = new HTMLNode("div");

    HTMLNode form = server.addFormChild(parent, "/target", "form-id");

    assertEquals("/target", form.getAttribute("action"));
    HTMLNode inputNode =
        form.getChildren().stream()
            .filter(child -> "input".equals(child.getFirstTag()))
            .findFirst()
            .orElseThrow();
    assertEquals("hidden", inputNode.getAttribute("type"));
    assertEquals("formPassword", inputNode.getAttribute("name"));
    assertEquals("secret-token", inputNode.getAttribute("value"));
  }

  @Test
  void getURL_whenHostProvided_buildsHttpUrlWithPort() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();

    String url = server.getURL("example.com");

    assertEquals("http://example.com:" + SimpleToadletServer.DEFAULT_FPROXY_PORT + "/", url);
  }

  @Test
  void allowPosts_whenUsingArrayBucketFactory_returnsFalse() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    server.setBucketFactory(new ArrayBucketFactory());

    assertFalse(server.allowPosts());
  }

  @Test
  void isAllowedFullAccess_whenAddressMatchesAllowList_returnsTrue() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();

    assertTrue(server.isAllowedFullAccess(InetAddress.getLoopbackAddress()));
    assertFalse(server.isAllowedFullAccess(InetAddress.getByName("8.8.8.8")));
  }

  @Test
  @SuppressWarnings("resource")
  void allowedHostsFullAccess_whenLoadedFromPersistentConfig_expectConfiguredValueRetained()
      throws Exception {
    // Arrange
    String configuredHost = "192.0.2.44";
    SimpleFieldSet initial = new SimpleFieldSet(true);
    initial.putSingle("fproxy.allowedHostsFullAccess", configuredHost);
    PersistentConfig rootConfig = new PersistentConfig(initial);
    SubConfig config = rootConfig.createSubConfig("fproxy");
    BucketFactory bucketFactory = mock(BucketFactory.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);

    SimpleToadletServer server;
    try (MockedStatic<NetworkInterface> netMock = mockStatic(NetworkInterface.class);
        MockedStatic<SSLNetworkInterface> sslMock = mockStatic(SSLNetworkInterface.class)) {
      NetworkInterface iface = mock(NetworkInterface.class);
      netMock
          .when(() -> NetworkInterface.create(anyInt(), any(), any(), any(), anyBoolean()))
          .thenReturn(iface);
      sslMock
          .when(() -> SSLNetworkInterface.createSsl(anyInt(), any(), any(), any(), anyBoolean()))
          .thenReturn(iface);
      server = new SimpleToadletServer(config, bucketFactory, executor);
    }

    // Act
    config.finishedInitialization();
    String callbackValue = config.getString("allowedHostsFullAccess");

    // Assert
    assertEquals(configuredHost, callbackValue);
    assertTrue(server.isAllowedFullAccess(InetAddress.getByName(configuredHost)));
    assertFalse(server.isAllowedFullAccess(InetAddress.getLoopbackAddress()));
  }

  @SuppressWarnings({"MustBeClosedChecker"})
  private SimpleToadletServer newServerWithDefaults() throws Exception {
    return newServerWithDefaults(new Config().createSubConfig("fproxy"));
  }

  @SuppressWarnings({"resource", "MustBeClosedChecker"})
  private SimpleToadletServer newServerWithDefaults(SubConfig config) throws Exception {
    BucketFactory bucketFactory = mock(BucketFactory.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);

    try (MockedStatic<NetworkInterface> netMock = mockStatic(NetworkInterface.class);
        MockedStatic<SSLNetworkInterface> sslMock = mockStatic(SSLNetworkInterface.class)) {
      NetworkInterface iface = mock(NetworkInterface.class);
      netMock
          .when(() -> NetworkInterface.create(anyInt(), any(), any(), any(), anyBoolean()))
          .thenReturn(iface);
      sslMock
          .when(() -> SSLNetworkInterface.createSsl(anyInt(), any(), any(), any(), anyBoolean()))
          .thenReturn(iface);
      return new SimpleToadletServer(config, bucketFactory, executor);
    }
  }

  private static class DummyToadlet extends Toadlet {
    private final String path;

    DummyToadlet(String path) {
      super(null);
      this.path = path;
    }

    @Override
    public void handleMethodGET(
        URI uri, network.crypta.support.api.HTTPRequest request, ToadletContext ctx) {
      // Intentionally no-op: tests only need a concrete Toadlet for registration/lookup behavior.
    }

    @Override
    public String path() {
      return path;
    }
  }

  private static final class ExceptedToadlet extends DummyToadlet
      implements LinkFilterExceptedToadlet {

    ExceptedToadlet(String path) {
      super(path);
    }

    @Override
    public boolean isLinkExcepted(URI link) {
      return link.getPath().startsWith(path());
    }
  }
}
