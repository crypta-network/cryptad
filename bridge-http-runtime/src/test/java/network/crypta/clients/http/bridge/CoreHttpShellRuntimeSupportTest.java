package network.crypta.clients.http.bridge;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.clients.http.BrowseContentClient;
import network.crypta.clients.http.ContentToadlet;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.HttpShellBrowseBootstrap;
import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.clients.http.InsertCompatibilityModes;
import network.crypta.clients.http.LegacyFProxyBrowseRouteRegistrar;
import network.crypta.clients.http.PushDataManagerHandle;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.clients.http.bridge.bookmark.CoreBookmarkRuntimeSupport;
import network.crypta.clients.http.updateableelements.PushDataManager;
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
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostConfigurationException;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import network.crypta.platform.apphost.runtime.LocalProcessAppHost;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.alerts.UserAlertSurface;
import network.crypta.runtime.services.NodeServicesSubsystem;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CoreHttpShellRuntimeSupportTest {
  private static final String TRUSTED_KEY_ID = "local-dev";

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

    UserAlertSurface actualAlerts = runtimeSupport.userAlerts();

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

  @Test
  void insertCompatibilityModes_whenInvoked_returnsDetachedOrderedModeNames() {
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(mock(NodeClientCore.class));

    InsertCompatibilityModes actualModes = runtimeSupport.insertCompatibilityModes();

    List<String> expectedModeNames =
        Arrays.stream(CompatibilityMode.values())
            .map(CompatibilityMode::intern)
            .filter(mode -> mode != CompatibilityMode.COMPAT_UNKNOWN)
            .map(CompatibilityMode::name)
            .distinct()
            .toList();
    assertEquals(expectedModeNames, actualModes.supportedModeNames());
    assertEquals(CompatibilityMode.COMPAT_DEFAULT.intern().name(), actualModes.defaultModeName());
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
      stubShutdownHookLookup(shutdownHooks, shutdownHook);
      runtimeSupport = new CoreHttpShellRuntimeSupport(core);
    }

    LocalProcessAppHost appHost =
        assertInstanceOf(LocalProcessAppHost.class, runtimeSupport.appHost());
    AppHostLayout layout = readLayout(appHost);
    assertEquals(expectedDataDir.toAbsolutePath(), layout.dataDir());
    assertEquals(expectedCacheDir.toAbsolutePath(), layout.cacheDir());
    assertEquals(expectedRunDir.toAbsolutePath(), layout.runDir());
    assertNotNull(runtimeSupport.appUpdateScheduler());
    assertNotNull(runtimeSupport.appUpdateService());
    verify(shutdownHook, times(2)).addEarlyJob(any(Thread.class));
  }

  @Test
  void appDataService_whenConstructedFromCore_usesHostManagedStoreRoot(@TempDir Path tempDir) {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());

    CoreHttpShellRuntimeSupport runtimeSupport;
    try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
        mockStatic(SemiOrderedShutdownHook.class)) {
      stubShutdownHookLookup(shutdownHooks, shutdownHook);
      runtimeSupport = new CoreHttpShellRuntimeSupport(core);
    }

    runtimeSupport
        .appDataService()
        .putRecord(
            "feed-reader",
            Map.of(
                "namespace",
                List.of("ui-state"),
                "key",
                List.of("startup"),
                "schemaVersion",
                List.of("1"),
                "contentType",
                List.of("application/json"),
                "valueJson",
                List.of("{}")));

    assertTrue(Files.exists(nodeDataDir.resolve("apps").resolve("durable-app-data")));
    assertFalse(
        Files.exists(
            nodeDataDir
                .resolve("apps")
                .resolve("data")
                .resolve("feed-reader")
                .resolve(".cryptad-app-data")));
    verify(shutdownHook, times(2)).addEarlyJob(any(Thread.class));
  }

  @Test
  void appVaultService_whenVaultStorageUnavailable_expectRuntimeStartsWithVaultUnavailable(
      @TempDir Path tempDir) throws IOException {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    Files.createDirectories(nodeDataDir.resolve("apps"));
    Files.writeString(nodeDataDir.resolve("apps").resolve("vault"), "not-a-directory");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());

    CoreHttpShellRuntimeSupport runtimeSupport;
    try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
        mockStatic(SemiOrderedShutdownHook.class)) {
      stubShutdownHookLookup(shutdownHooks, shutdownHook);
      runtimeSupport = new CoreHttpShellRuntimeSupport(core);
    }

    assertNotNull(runtimeSupport.appHost());
    assertNull(runtimeSupport.appVaultService());
    assertNotNull(runtimeSupport.appUpdateScheduler());
    assertNotNull(runtimeSupport.appUpdateService());
    verify(shutdownHook, times(2)).addEarlyJob(any(Thread.class));
  }

  @Test
  void appHost_whenConstructedFromCore_expectUnsignedInstallRejectedByProductionPolicy(
      @TempDir Path tempDir) throws IOException {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));

    CoreHttpShellRuntimeSupport runtimeSupport;
    try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
        mockStatic(SemiOrderedShutdownHook.class)) {
      stubShutdownHookLookup(shutdownHooks, shutdownHook);
      runtimeSupport = new CoreHttpShellRuntimeSupport(core);
    }

    AppBundleVerificationException exception =
        assertThrows(
            AppBundleVerificationException.class,
            () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

    assertEquals("missing signature sidecar", exception.getMessage());
  }

  @Test
  void appHost_whenAllowUnsignedAndCaseVariantSidecarPresent_expectSignedVerificationRequired(
      @TempDir Path tempDir) throws IOException {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));
    Files.writeString(stagedDir.resolve("CRYPTAD-APP.DIGESTS"), "stale-digest");
    String previousAllowUnsigned = System.getProperty("cryptad.apphost.allowUnsigned");

    try {
      System.setProperty("cryptad.apphost.allowUnsigned", "true");

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      AppBundleVerificationException exception =
          assertThrows(
              AppBundleVerificationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

      assertEquals("missing signature sidecar", exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.apphost.allowUnsigned", previousAllowUnsigned);
    }
  }

  @Test
  void appHost_whenTrustedKeyConfigured_expectSignedInstallAccepted(@TempDir Path tempDir)
      throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path stagedDir = stageSignedApp(tempDir.resolve("staged-signed"), keyPair);
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");

    try {
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      assertEquals(
          "demo-app", runtimeSupport.appHost().installFromDirectory(stagedDir).manifest().appId());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
    }
  }

  @Test
  void appHost_whenTrustedPublicKeyFileContainsRawDer_expectSignedInstallAccepted(
      @TempDir Path tempDir) throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path stagedDir = stageSignedApp(tempDir.resolve("staged-raw-der"), keyPair);
    Path publicKeyFile = tempDir.resolve("public-key.der");
    Files.write(publicKeyFile, keyPair.getPublic().getEncoded());
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");
    String previousPublicKeyFile = System.getProperty("cryptad.apphost.trustedPublicKeyFile");

    try {
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.clearProperty("cryptad.apphost.trustedPublicKeyBase64");
      System.setProperty("cryptad.apphost.trustedPublicKeyFile", publicKeyFile.toString());

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      assertEquals(
          "demo-app", runtimeSupport.appHost().installFromDirectory(stagedDir).manifest().appId());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyFile", previousPublicKeyFile);
    }
  }

  @Test
  void appHost_whenTrustedKeysFileIsUnreadable_expectBootstrapSucceedsAndInstallFailsOnDemand(
      @TempDir Path tempDir) throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));
    String previousTrustedKeysFile = System.getProperty("cryptad.apphost.trustedKeysFile");

    try {
      System.setProperty(
          "cryptad.apphost.trustedKeysFile",
          tempDir.resolve("missing-trusted-keys.properties").toString());

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      AppHostConfigurationException exception =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

      assertEquals("Failed to load trusted app keys file.", exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeysFile", previousTrustedKeysFile);
    }
  }

  @Test
  void appHost_whenTrustedKeyIdDuplicatesTrustedKeysFile_expectInstallFailsWithVerificationError(
      @TempDir Path tempDir) throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path trustedKeysFile = tempDir.resolve("trusted-keys.properties");
    Files.writeString(
        trustedKeysFile,
        """
        trusted.keys.version=1
        key.0.id=%s
        key.0.algorithm=Ed25519
        key.0.public.key.base64=%s
        """
            .formatted(
                TRUSTED_KEY_ID,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())),
        StandardCharsets.UTF_8);
    String previousTrustedKeysFile = System.getProperty("cryptad.apphost.trustedKeysFile");
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");

    try {
      System.setProperty("cryptad.apphost.trustedKeysFile", trustedKeysFile.toString());
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      AppHostConfigurationException exception =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

      assertEquals("duplicate trusted key id: " + TRUSTED_KEY_ID, exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeysFile", previousTrustedKeysFile);
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
    }
  }

  @Test
  void appHost_whenTrustedPublicKeyConfiguredWithoutKeyId_expectInstallFailsWithVerificationError(
      @TempDir Path tempDir) throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");
    String previousPublicKeyFile = System.getProperty("cryptad.apphost.trustedPublicKeyFile");

    try {
      System.clearProperty("cryptad.apphost.trustedKeyId");
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
      System.clearProperty("cryptad.apphost.trustedPublicKeyFile");

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      AppHostConfigurationException exception =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

      assertEquals(
          "Trusted app public key material requires trusted app key id.", exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyFile", previousPublicKeyFile);
    }
  }

  @Test
  void appHost_whenConflictingTrustedPublicKeyInputsProvided_expectConfigurationFailure(
      @TempDir Path tempDir) throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path publicKeyFile = tempDir.resolve("public.pem");
    Files.writeString(
        publicKeyFile,
        Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
        StandardCharsets.UTF_8);
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");
    String previousPublicKeyFile = System.getProperty("cryptad.apphost.trustedPublicKeyFile");

    try {
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
      System.setProperty("cryptad.apphost.trustedPublicKeyFile", publicKeyFile.toString());

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      AppHostConfigurationException exception =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

      assertEquals(
          "Trusted app public key material must be configured by base64 or file, not both.",
          exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyFile", previousPublicKeyFile);
    }
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
  void createBrowseBootstrap_whenInvoked_constructsDependenciesAndReturnsBootstrap() {
    NodeClientCore core = mock(NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RuntimePorts bootstrapRuntimePorts = mock(RuntimePorts.class);
    AtomicReference<List<Object>> bookmarkManagerArguments = new AtomicReference<>();
    AtomicReference<List<Object>> fetchTrackerArguments = new AtomicReference<>();
    AtomicReference<List<Object>> browseRootArguments = new AtomicReference<>();
    when(core.getAlerts()).thenReturn(alerts);
    when(core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true)).thenReturn(client);
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
                (_, invocation) -> browseRootArguments.set(List.copyOf(invocation.arguments())))) {
      HttpShellBrowseBootstrap bootstrap = runtimeSupport.createBrowseBootstrap(true);

      assertEquals(1, bookmarkManagers.constructed().size());
      assertEquals(1, fetchTrackers.constructed().size());
      assertEquals(1, fproxies.constructed().size());
      assertInstanceOf(CoreBookmarkRuntimeSupport.class, bookmarkManagerArguments.get().get(0));
      assertSame(alerts, bookmarkManagerArguments.get().get(1));
      assertEquals(Boolean.TRUE, bookmarkManagerArguments.get().get(2));
      assertSame(fetchContext, fetchTrackerArguments.get().get(0));
      assertInstanceOf(CoreFProxyRuntimeSupport.class, fetchTrackerArguments.get().get(1));
      assertNotNull(fetchTrackerArguments.get().get(2));
      assertInstanceOf(BrowseContentClient.class, browseRootArguments.get().get(0));
      assertInstanceOf(CoreFProxyRuntimeSupport.class, browseRootArguments.get().get(1));
      assertSame(fetchTrackers.constructed().getFirst(), browseRootArguments.get().get(2));
      assertSame(bookmarkManagers.constructed().getFirst(), bootstrap.bookmarkManager());
      assertSame(runtimeSupport.appHost(), bootstrap.appHost());
      assertSame(fproxies.constructed().getFirst(), bootstrap.browseRoot());
      assertContentToadlet(fproxies.constructed().getFirst());
      LegacyFProxyBrowseRouteRegistrar browseRouteRegistrar =
          assertInstanceOf(
              LegacyFProxyBrowseRouteRegistrar.class, bootstrap.browseRouteRegistrar());
      assertInstanceOf(BrowseContentClient.class, readRegistrarClient(browseRouteRegistrar));
      verify(core, never()).getRuntimePorts();
      verifyNoInteractions(bootstrapRuntimePorts);
      verify(core, never()).getEndpoints();
    }
  }

  @Test
  void createBrowseBootstrap_whenInitializerInvoked_seedsSharedForceLinkRandom() {
    NodeClientCore core = mock(NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    RandomnessPort randomnessPort = mock(RandomnessPort.class);
    when(core.getAlerts()).thenReturn(alerts);
    when(core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true)).thenReturn(client);
    when(client.getFetchContext()).thenReturn(fetchContext);
    when(runtimePorts.randomness()).thenReturn(randomnessPort);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    try (var _ = mockConstruction(BookmarkManager.class)) {
      HttpShellBrowseBootstrap bootstrap = runtimeSupport.createBrowseBootstrap(true);

      bootstrap.sharedShellInitializer().accept(runtimePorts);
    }

    ArgumentCaptor<byte[]> randomCaptor = ArgumentCaptor.forClass(byte[].class);
    verify(runtimePorts).randomness();
    verify(randomnessPort).fillSecureRandom(randomCaptor.capture());
    assertEquals(32, randomCaptor.getValue().length);
  }

  @Test
  void createPushDataManagerHandle_whenInvoked_constructsConcreteBrowseManager() {
    NodeClientCore core = mock(NodeClientCore.class);
    Ticker ticker = mock(Ticker.class);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    try (MockedConstruction<PushDataManager> pushManagers =
        mockConstruction(
            PushDataManager.class,
            (_, invocation) -> assertSame(ticker, invocation.arguments().getFirst()))) {
      PushDataManagerHandle handle = runtimeSupport.createPushDataManagerHandle(ticker);

      assertEquals(1, pushManagers.constructed().size());
      assertSame(pushManagers.constructed().getFirst(), handle);
    }
  }

  @Test
  void createPushDataManagerHandle_whenTickerNull_throwsNullPointerException() {
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(mock(NodeClientCore.class));

    assertThrows(
        NullPointerException.class, () -> runtimeSupport.createPushDataManagerHandle(null));
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

  private static BrowseContentClient readRegistrarClient(
      LegacyFProxyBrowseRouteRegistrar registrar) {
    try {
      Field field = registrar.getClass().getDeclaredField("client");
      field.setAccessible(true);
      return (BrowseContentClient) field.get(registrar);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed reading field 'client'", e);
    }
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

  private static Path stageUnsignedApp(Path stagedDir) throws IOException {
    Path binDir = Files.createDirectories(stagedDir.resolve("bin"));
    Path launcher = binDir.resolve("launch.sh");
    Files.writeString(
        launcher,
        """
        #!/bin/sh
        exit 0
        """,
        StandardCharsets.UTF_8);
    Files.writeString(
        stagedDir.resolve(AppManifestParser.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=demo-app
        app.name=Demo App
        app.version=1.0.0
        app.exec=bin/launch.sh
        app.ui.entry=/
        app.permissions=network.access
        quota.data.bytes=1024
        quota.cache.bytes=512
        """,
        StandardCharsets.UTF_8);
    return stagedDir;
  }

  private static Path stageSignedApp(Path stagedDir, KeyPair keyPair) throws IOException {
    Path unsigned = stageUnsignedApp(stagedDir);
    AppBundleSigner.sign(unsigned, TRUSTED_KEY_ID, keyPair.getPrivate());
    return unsigned;
  }

  private static void stubShutdownHookLookup(
      MockedStatic<SemiOrderedShutdownHook> shutdownHooks, SemiOrderedShutdownHook shutdownHook) {
    shutdownHooks
        .when(() -> assertNotSame(shutdownHook, SemiOrderedShutdownHook.get()))
        .thenReturn(shutdownHook);
  }

  private static void restoreSystemProperty(String name, String value) {
    if (value == null) {
      System.clearProperty(name);
    } else {
      System.setProperty(name, value);
    }
  }

  private static void assertContentToadlet(Toadlet toadlet) {
    assertInstanceOf(
        ContentToadlet.class,
        toadlet,
        toadlet.getClass().getName() + " must extend ContentToadlet");
  }

  private record NetworkListenerContext(
      CoreHttpShellRuntimeSupport runtimeSupport,
      AtomicReference<SecurityLevelListener<NETWORK_THREAT_LEVEL>> listener) {}

  private record PhysicalListenerContext(
      CoreHttpShellRuntimeSupport runtimeSupport,
      AtomicReference<SecurityLevelListener<PHYSICAL_THREAT_LEVEL>> listener) {}
}
