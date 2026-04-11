package network.crypta.clients.http.bridge;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.HttpShellFProxyBootstrap;
import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.clients.http.bridge.bookmark.CoreBookmarkRuntimeSupport;
import network.crypta.config.PersistentConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.RequestStarter;
import network.crypta.node.SecurityLevelListener;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.SecurityLevels;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.runtime.LocalProcessAppHost;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.services.NodeServicesSubsystem;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CoreHttpShellRuntimeSupportTest {

  @Test
  void constructor_whenCoreIsNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new CoreHttpShellRuntimeSupport(null));
  }

  @Test
  void runtimePorts_whenCoreProvidesPorts_returnsSamePorts() {
    NodeClientCore core = mock(NodeClientCore.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    when(core.getRuntimePorts()).thenReturn(runtimePorts);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    RuntimePorts actualRuntimePorts = runtimeSupport.runtimePorts();

    assertSame(runtimePorts, actualRuntimePorts);
  }

  @Test
  void config_whenNodeProvidesConfig_returnsSameConfig() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    PersistentConfig config = mock(PersistentConfig.class);
    when(core.getNode()).thenReturn(node);
    when(node.getConfig()).thenReturn(config);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    PersistentConfig actualConfig = (PersistentConfig) runtimeSupport.config();

    assertSame(config, actualConfig);
  }

  @Test
  void ticker_whenNodeProvidesTicker_returnsSameTicker() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    Ticker ticker = mock(Ticker.class);
    when(core.getNode()).thenReturn(node);
    when(node.network()).thenReturn(network);
    when(network.ticker()).thenReturn(ticker);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    Ticker actualTicker = runtimeSupport.ticker();

    assertSame(ticker, actualTicker);
  }

  @Test
  void userAlerts_whenCoreProvidesAlerts_returnsSameAlerts() {
    NodeClientCore core = mock(NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    when(core.getAlerts()).thenReturn(alerts);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    UserAlertManager actualAlerts = runtimeSupport.userAlerts();

    assertSame(alerts, actualAlerts);
  }

  @Test
  void formPassword_whenCoreProvidesPassword_returnsSamePassword() {
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getFormPassword()).thenReturn("secret-token");
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    String formPassword = runtimeSupport.formPassword();

    assertEquals("secret-token", formPassword);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void allowUploadFrom_whenCoreReturnsDecision_propagatesDecision(boolean allowed) {
    NodeClientCore core = mock(NodeClientCore.class);
    File uploadTarget = new File("allowed-upload.txt");
    when(core.allowUploadFrom(uploadTarget)).thenReturn(allowed);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    boolean uploadAllowed = runtimeSupport.allowUploadFrom(uploadTarget);

    assertEquals(allowed, uploadAllowed);
  }

  @Test
  void storeConfig_whenInvoked_storesConfig() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    PersistentConfig config = mock(PersistentConfig.class);
    when(core.getNode()).thenReturn(node);
    when(node.getConfig()).thenReturn(config);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    runtimeSupport.storeConfig();

    verify(config).store();
  }

  @Test
  void canRedirectToWizard_whenUsingCoreRuntime_returnsTrue() {
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(mock(NodeClientCore.class));

    boolean canRedirect = runtimeSupport.canRedirectToWizard();

    assertTrue(canRedirect);
  }

  @Test
  void addNetworkThreatLevelListener_whenListenerIsNull_throwsNullPointerException() {
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(mock(NodeClientCore.class));

    assertThrows(
        NullPointerException.class, () -> runtimeSupport.addNetworkThreatLevelListener(null));
  }

  @Test
  void addPhysicalThreatLevelListener_whenListenerIsNull_throwsNullPointerException() {
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(mock(NodeClientCore.class));

    assertThrows(
        NullPointerException.class, () -> runtimeSupport.addPhysicalThreatLevelListener(null));
  }

  @Test
  void appHost_whenConstructedFromCore_usesCurrentNodeDirectories(@TempDir Path tempDir) {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path expectedDataDir = tempDir.resolve("node");
    Path expectedCacheDir = tempDir.resolve("persistent-temp");
    Path expectedRunDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(expectedDataDir.toFile());
    when(runDir.dir()).thenReturn(expectedRunDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(expectedCacheDir.toFile());

    CoreHttpShellRuntimeSupport runtimeSupport;
    try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
        mockStatic(SemiOrderedShutdownHook.class)) {
      shutdownHooks
          .when(() -> assertNotSame(shutdownHook, SemiOrderedShutdownHook.get()))
          .thenReturn(shutdownHook);
      runtimeSupport = new CoreHttpShellRuntimeSupport(core);
    }

    LocalProcessAppHost appHost =
        assertInstanceOf(LocalProcessAppHost.class, runtimeSupport.appHost());
    AppHostLayout layout = readLayout(appHost);
    assertEquals(expectedDataDir.toAbsolutePath(), layout.dataDir());
    assertEquals(expectedCacheDir.toAbsolutePath(), layout.cacheDir());
    assertEquals(expectedRunDir.toAbsolutePath(), layout.runDir());
    verify(shutdownHook).addEarlyJob(any(Thread.class));
  }

  @ParameterizedTest
  @MethodSource("networkThreatLevelMappings")
  void addNetworkThreatLevelListener_whenSecurityLevelsChange_mapsDetachedEnums(
      NETWORK_THREAT_LEVEL oldLevel,
      HttpShellRuntimeSupport.NetworkThreatLevel expectedOldLevel,
      NETWORK_THREAT_LEVEL newLevel,
      HttpShellRuntimeSupport.NetworkThreatLevel expectedNewLevel) {
    NetworkListenerContext context = newNetworkListenerContext();
    AtomicReference<HttpShellRuntimeSupport.NetworkThreatLevel> actualOldLevel =
        new AtomicReference<>();
    AtomicReference<HttpShellRuntimeSupport.NetworkThreatLevel> actualNewLevel =
        new AtomicReference<>();

    context.runtimeSupport.addNetworkThreatLevelListener(
        (capturedOldLevel, capturedNewLevel) -> {
          actualOldLevel.set(capturedOldLevel);
          actualNewLevel.set(capturedNewLevel);
        });

    assertNotNull(context.listener.get());

    context.listener.get().onChange(oldLevel, newLevel);

    assertEquals(expectedOldLevel, actualOldLevel.get());
    assertEquals(expectedNewLevel, actualNewLevel.get());
  }

  @ParameterizedTest
  @MethodSource("physicalThreatLevelMappings")
  void addPhysicalThreatLevelListener_whenSecurityLevelsChange_mapsDetachedEnums(
      PHYSICAL_THREAT_LEVEL oldLevel,
      HttpShellRuntimeSupport.PhysicalThreatLevel expectedOldLevel,
      PHYSICAL_THREAT_LEVEL newLevel,
      HttpShellRuntimeSupport.PhysicalThreatLevel expectedNewLevel) {
    PhysicalListenerContext context = newPhysicalListenerContext();
    AtomicReference<HttpShellRuntimeSupport.PhysicalThreatLevel> actualOldLevel =
        new AtomicReference<>();
    AtomicReference<HttpShellRuntimeSupport.PhysicalThreatLevel> actualNewLevel =
        new AtomicReference<>();

    context.runtimeSupport.addPhysicalThreatLevelListener(
        (capturedOldLevel, capturedNewLevel) -> {
          actualOldLevel.set(capturedOldLevel);
          actualNewLevel.set(capturedNewLevel);
        });

    assertNotNull(context.listener.get());

    context.listener.get().onChange(oldLevel, newLevel);

    assertEquals(expectedOldLevel, actualOldLevel.get());
    assertEquals(expectedNewLevel, actualNewLevel.get());
  }

  @Test
  void createFProxyBootstrap_whenInvoked_constructsDependenciesAndReturnsBootstrap() {
    NodeClientCore core = mock(NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    ClientContext clientContext = mock(ClientContext.class);
    FetchContext fetchContext = mock(FetchContext.class);
    AtomicReference<List<Object>> bookmarkManagerArguments = new AtomicReference<>();
    AtomicReference<List<Object>> fetchTrackerArguments = new AtomicReference<>();
    AtomicReference<List<Object>> fproxyArguments = new AtomicReference<>();
    when(core.getAlerts()).thenReturn(alerts);
    when(core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true)).thenReturn(client);
    when(core.getClientContext()).thenReturn(clientContext);
    when(client.getFetchContext()).thenReturn(fetchContext);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    try (MockedConstruction<BookmarkManager> bookmarkManagers =
            mockConstruction(
                BookmarkManager.class,
                (_, invocation) ->
                    bookmarkManagerArguments.set(List.copyOf(invocation.arguments())));
        MockedConstruction<FProxyFetchTracker> fetchTrackers =
            mockConstruction(
                FProxyFetchTracker.class,
                (_, invocation) -> fetchTrackerArguments.set(List.copyOf(invocation.arguments())));
        MockedConstruction<FProxyToadlet> fproxies =
            mockConstruction(
                FProxyToadlet.class,
                (_, invocation) -> fproxyArguments.set(List.copyOf(invocation.arguments())))) {
      HttpShellFProxyBootstrap bootstrap = runtimeSupport.createFProxyBootstrap(true);

      assertEquals(1, bookmarkManagers.constructed().size());
      assertEquals(1, fetchTrackers.constructed().size());
      assertEquals(1, fproxies.constructed().size());
      assertInstanceOf(CoreBookmarkRuntimeSupport.class, bookmarkManagerArguments.get().get(0));
      assertSame(alerts, bookmarkManagerArguments.get().get(1));
      assertEquals(Boolean.TRUE, bookmarkManagerArguments.get().get(2));
      assertSame(clientContext, fetchTrackerArguments.get().get(0));
      assertSame(fetchContext, fetchTrackerArguments.get().get(1));
      assertNotNull(fetchTrackerArguments.get().get(2));
      assertSame(client, fproxyArguments.get().get(0));
      assertInstanceOf(CoreFProxyRuntimeSupport.class, fproxyArguments.get().get(1));
      assertSame(fetchTrackers.constructed().getFirst(), fproxyArguments.get().get(2));
      assertSame(bookmarkManagers.constructed().getFirst(), bootstrap.bookmarkManager());
      assertSame(client, bootstrap.client());
      assertSame(runtimeSupport.appHost(), bootstrap.appHost());
      assertSame(fproxies.constructed().getFirst(), bootstrap.fproxy());
      verify(core, never()).getEndpoints();
    }
  }

  @Test
  void createAppHostShutdownJob_whenAppsRunning_stopsEachRunningApp() throws Exception {
    AppHost appHost = mock(AppHost.class);
    when(appHost.listRunning())
        .thenReturn(List.of(runningAppSnapshot("alpha"), runningAppSnapshot("beta")));
    when(appHost.stop("alpha")).thenReturn(true);
    doThrow(new IOException("boom")).when(appHost).stop("beta");

    Thread shutdownJob = CoreHttpShellRuntimeSupport.createAppHostShutdownJob(appHost);
    shutdownJob.start();
    shutdownJob.join();

    verify(appHost).stop("alpha");
    verify(appHost).stop("beta");
  }

  private static Stream<Arguments> networkThreatLevelMappings() {
    return Stream.of(
        Arguments.of(
            NETWORK_THREAT_LEVEL.LOW,
            HttpShellRuntimeSupport.NetworkThreatLevel.LOW,
            NETWORK_THREAT_LEVEL.NORMAL,
            HttpShellRuntimeSupport.NetworkThreatLevel.NORMAL),
        Arguments.of(
            NETWORK_THREAT_LEVEL.NORMAL,
            HttpShellRuntimeSupport.NetworkThreatLevel.NORMAL,
            NETWORK_THREAT_LEVEL.HIGH,
            HttpShellRuntimeSupport.NetworkThreatLevel.HIGH),
        Arguments.of(
            NETWORK_THREAT_LEVEL.HIGH,
            HttpShellRuntimeSupport.NetworkThreatLevel.HIGH,
            NETWORK_THREAT_LEVEL.MAXIMUM,
            HttpShellRuntimeSupport.NetworkThreatLevel.MAXIMUM),
        Arguments.of(
            NETWORK_THREAT_LEVEL.MAXIMUM,
            HttpShellRuntimeSupport.NetworkThreatLevel.MAXIMUM,
            NETWORK_THREAT_LEVEL.LOW,
            HttpShellRuntimeSupport.NetworkThreatLevel.LOW));
  }

  private static Stream<Arguments> physicalThreatLevelMappings() {
    return Stream.of(
        Arguments.of(
            PHYSICAL_THREAT_LEVEL.LOW,
            HttpShellRuntimeSupport.PhysicalThreatLevel.LOW,
            PHYSICAL_THREAT_LEVEL.NORMAL,
            HttpShellRuntimeSupport.PhysicalThreatLevel.NORMAL),
        Arguments.of(
            PHYSICAL_THREAT_LEVEL.NORMAL,
            HttpShellRuntimeSupport.PhysicalThreatLevel.NORMAL,
            PHYSICAL_THREAT_LEVEL.HIGH,
            HttpShellRuntimeSupport.PhysicalThreatLevel.HIGH),
        Arguments.of(
            PHYSICAL_THREAT_LEVEL.HIGH,
            HttpShellRuntimeSupport.PhysicalThreatLevel.HIGH,
            PHYSICAL_THREAT_LEVEL.MAXIMUM,
            HttpShellRuntimeSupport.PhysicalThreatLevel.MAXIMUM),
        Arguments.of(
            PHYSICAL_THREAT_LEVEL.MAXIMUM,
            HttpShellRuntimeSupport.PhysicalThreatLevel.MAXIMUM,
            PHYSICAL_THREAT_LEVEL.LOW,
            HttpShellRuntimeSupport.PhysicalThreatLevel.LOW));
  }

  private static NetworkListenerContext newNetworkListenerContext() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    SecurityLevels securityLevels = mock(SecurityLevels.class);
    AtomicReference<SecurityLevelListener<NETWORK_THREAT_LEVEL>> listener = new AtomicReference<>();
    when(core.getNode()).thenReturn(node);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    doAnswer(
            invocation -> {
              listener.set(invocation.getArgument(0));
              return null;
            })
        .when(securityLevels)
        .addNetworkThreatLevelListener(any());
    return new NetworkListenerContext(runtimeSupport(core), listener);
  }

  private static PhysicalListenerContext newPhysicalListenerContext() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    SecurityLevels securityLevels = mock(SecurityLevels.class);
    AtomicReference<SecurityLevelListener<PHYSICAL_THREAT_LEVEL>> listener =
        new AtomicReference<>();
    when(core.getNode()).thenReturn(node);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    doAnswer(
            invocation -> {
              listener.set(invocation.getArgument(0));
              return null;
            })
        .when(securityLevels)
        .addPhysicalThreatLevelListener(any());
    return new PhysicalListenerContext(runtimeSupport(core), listener);
  }

  private static CoreHttpShellRuntimeSupport runtimeSupport(NodeClientCore core) {
    return new CoreHttpShellRuntimeSupport(core, mock(AppHost.class));
  }

  private static AppHostLayout readLayout(LocalProcessAppHost appHost) {
    try {
      Field field = appHost.getClass().getDeclaredField("layout");
      field.setAccessible(true);
      return (AppHostLayout) field.get(appHost);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed reading field 'layout'", e);
    }
  }

  private static RunningAppSnapshot runningAppSnapshot(String appId) {
    AppManifest manifest =
        new AppManifest(
            1,
            appId,
            "Demo App",
            "1.0.0",
            "bin/launch",
            "/",
            List.of("network.access"),
            1024L,
            512L);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            appId,
            Path.of("build", "test-runtime", "apphost", "installed", appId).toAbsolutePath(),
            Path.of("build", "test-runtime", "apphost", "data", appId).toAbsolutePath(),
            Path.of("build", "test-runtime", "apphost", "cache", appId).toAbsolutePath(),
            Path.of("build", "test-runtime", "apphost", "run", appId).toAbsolutePath());
    return new RunningAppSnapshot(
        manifest, paths, "token-" + appId, 4242L, Instant.parse("2024-01-02T03:04:05Z"));
  }

  private record NetworkListenerContext(
      CoreHttpShellRuntimeSupport runtimeSupport,
      AtomicReference<SecurityLevelListener<NETWORK_THREAT_LEVEL>> listener) {}

  private record PhysicalListenerContext(
      CoreHttpShellRuntimeSupport runtimeSupport,
      AtomicReference<SecurityLevelListener<PHYSICAL_THREAT_LEVEL>> listener) {}
}
