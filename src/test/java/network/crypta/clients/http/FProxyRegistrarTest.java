package network.crypta.clients.http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import network.crypta.clients.http.ajaxpush.DismissAlertToadlet;
import network.crypta.clients.http.ajaxpush.LogWritebackToadlet;
import network.crypta.clients.http.ajaxpush.PushDataToadlet;
import network.crypta.clients.http.ajaxpush.PushFailoverToadlet;
import network.crypta.clients.http.ajaxpush.PushKeepaliveToadlet;
import network.crypta.clients.http.ajaxpush.PushLeavingToadlet;
import network.crypta.clients.http.ajaxpush.PushNotificationToadlet;
import network.crypta.clients.http.ajaxpush.PushTesterToadlet;
import network.crypta.config.Config;
import network.crypta.config.IntCallback;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.fs.readiness.LauncherReadinessInfo;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.webshell.routes.WebShellPaths;
import network.crypta.runtime.spi.CoreUpdateActionPort;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.ToadletSymlinkPort;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.runtime.spi.WelcomeActionPort;
import network.crypta.runtime.spi.WelcomePagePort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static network.crypta.runtime.updater.UpdaterPaths.CORE_UPDATE_PATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class FProxyRegistrarTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private RuntimePorts runtimePorts;

  @Mock private BrowseContentClient client;
  @Mock private AppHost appHost;
  @Mock private Toadlet browseRoot;
  @Mock private QueueCompletionPort queueCompletionPort;
  @Mock private WelcomePagePort welcomePagePort;
  @Mock private DarknetConnectionsPort darknetConnectionsPort;
  @Mock private DarknetMessagingPort darknetMessagingPort;
  @Mock private LifecyclePort lifecyclePort;
  @Mock private WelcomeActionPort welcomeActionPort;
  @Mock private FirstTimeWizardPort firstTimeWizardPort;
  @Mock private SecurityLevelsPort securityLevelsPort;
  @Mock private CoreUpdateActionPort coreUpdateActionPort;
  @Mock private ToadletSymlinkPort toadletSymlinkPort;
  @Mock private TransferAccessPort transferAccess;
  @Mock private SimpleToadletServer server;
  @Mock private LegacyHttpBrowseRouteRegistrar browseRouteRegistrar;

  private Config config;

  @BeforeEach
  void setUp() {
    config = new Config();
    SubConfig nodeConfig = config.createSubConfig("node");
    registerBandwidthOption(nodeConfig, "outputBandwidthLimit", 1024);
    registerBandwidthOption(nodeConfig, "inputBandwidthLimit", 2048);
    nodeConfig.finishedInitialization();

    SubConfig alphaConfig = config.createSubConfig("alpha");
    alphaConfig.finishedInitialization();
    SubConfig securityLevelsConfig = config.createSubConfig("security-levels");
    securityLevelsConfig.finishedInitialization();

    when(runtimePorts.queueCompletion()).thenReturn(queueCompletionPort);
    when(runtimePorts.welcomePage()).thenReturn(welcomePagePort);
    when(runtimePorts.darknetConnections()).thenReturn(darknetConnectionsPort);
    when(runtimePorts.darknetMessaging()).thenReturn(darknetMessagingPort);
    when(runtimePorts.lifecycle()).thenReturn(lifecyclePort);
    when(runtimePorts.welcomeAction()).thenReturn(welcomeActionPort);
    when(runtimePorts.firstTimeWizard()).thenReturn(firstTimeWizardPort);
    when(runtimePorts.securityLevels()).thenReturn(securityLevelsPort);
    when(runtimePorts.coreUpdateAction()).thenReturn(coreUpdateActionPort);
    when(runtimePorts.toadletSymlinks()).thenReturn(toadletSymlinkPort);
    when(runtimePorts.transferAccess()).thenReturn(transferAccess);
    when(toadletSymlinkPort.loadConfiguredSymlinks()).thenReturn(List.of());
  }

  @Test
  void maybeCreateFProxyEtc_whenInvoked_registersMenusSetsFProxyAndStartsQueueCompletion() {
    FProxyRegistrar.maybeCreateFProxyEtc(
        dependencies(new LegacyFProxyBrowseRouteRegistrar(client)), server);

    verify(server)
        .registerMenu(
            "/", LegacyHttpCategories.CATEGORY_BROWSING, "FProxyToadlet.categoryTitleBrowsing");
    verify(server)
        .registerMenu(
            eq(LegacyAdminRetirementRegistry.require("queue-downloads").replacementUrl()),
            eq(LegacyHttpCategories.CATEGORY_QUEUE),
            eq("FProxyToadlet.categoryTitleQueue"),
            eq(QueueToadlet.PATH_DOWNLOADS),
            eq(false),
            any(LinkEnabledCallback.class),
            any(LinkEnabledCallback.class));
    verify(server)
        .registerMenu(
            eq(LegacyAdminRetirementRegistry.require("friends").replacementUrl()),
            eq(LegacyHttpCategories.CATEGORY_FRIENDS),
            eq("FProxyToadlet.categoryTitleFriends"),
            eq(LegacyHttpPaths.FRIENDS_PATH),
            any(LinkEnabledCallback.class));
    verify(server)
        .registerMenu("/chat/", "FProxyToadlet.categoryChat", "FProxyToadlet.categoryTitleChat");
    verify(server)
        .registerMenu(
            eq(WebShellPaths.SHELL_ROOT),
            eq(LegacyHttpCategories.CATEGORY_STATUS),
            eq("FProxyToadlet.categoryTitleStatus"),
            eq("/alerts/"),
            any(LinkEnabledCallback.class));
    verify(server)
        .registerMenu(
            eq(LegacyAdminRetirementRegistry.require("config").replacementUrl()),
            eq(LegacyHttpCategories.CATEGORY_CONFIG),
            eq("FProxyToadlet.categoryTitleConfig"),
            eq(SecurityLevelsToadlet.PATH),
            any(LinkEnabledCallback.class));

    InOrder queueCompletionOrder = inOrder(queueCompletionPort);
    queueCompletionOrder.verify(queueCompletionPort).ensureTrackingStarted(false);
    queueCompletionOrder.verify(queueCompletionPort).ensureTrackingStarted(true);

    List<RegisteredToadlet> registrations = capturedRegistrations();
    assertTrue(
        registrations.stream()
            .anyMatch(
                registered ->
                    registered.toadlet() == browseRoot
                        && "/".equals(registered.registration().urlPrefix())));
    assertTrue(
        registrations.stream()
            .anyMatch(
                registered ->
                    QueueToadlet.PATH_DOWNLOADS.equals(registered.registration().urlPrefix())));
    assertTrue(
        registrations.stream()
            .anyMatch(
                registered ->
                    QueueToadlet.PATH_UPLOADS.equals(registered.registration().urlPrefix())));
    assertTrue(
        registrations.stream()
            .anyMatch(
                registered ->
                    FirstTimeWizardToadlet.TOADLET_URL.equals(
                        registered.registration().urlPrefix())));
    assertTrue(
        registrations.stream()
            .anyMatch(
                registered ->
                    registered.toadlet() instanceof WebShellToadlet
                        && WebShellPaths.SHELL_ROOT.equals(registered.registration().urlPrefix())));
    RegisteredToadlet wizardRegistration =
        registrations.stream()
            .filter(
                registered ->
                    FirstTimeWizardToadlet.TOADLET_URL.equals(
                        registered.registration().urlPrefix()))
            .findFirst()
            .orElseThrow();
    assertSame(firstTimeWizardPort, readWizardPortField(wizardRegistration.toadlet()));
    RegisteredToadlet symlinkerRegistration =
        registrations.stream()
            .filter(registered -> registered.toadlet() instanceof SymlinkerToadlet)
            .findFirst()
            .orElseThrow();
    assertSame(toadletSymlinkPort, readField(symlinkerRegistration.toadlet(), "symlinkPort"));
    RegisteredToadlet coreActionRegistration =
        registrations.stream()
            .filter(
                registered ->
                    registered.toadlet()
                        instanceof network.crypta.clients.http.updater.CoreActionToadlet)
            .findFirst()
            .orElseThrow();
    assertSame(
        coreUpdateActionPort, readField(coreActionRegistration.toadlet(), "coreUpdateActionPort"));
    RegisteredToadlet fileInsertWizardRegistration =
        registrations.stream()
            .filter(
                registered ->
                    FileInsertWizardToadlet.PATH.equals(registered.registration().urlPrefix()))
            .findFirst()
            .orElseThrow();
    FileInsertWizardToadletRuntimePorts fileInsertWizardRuntimePorts =
        (FileInsertWizardToadletRuntimePorts)
            readField(fileInsertWizardRegistration.toadlet(), "runtimePorts");
    assertSame(securityLevelsPort, fileInsertWizardRuntimePorts.securityLevelsPort());
    RegisteredToadlet bookmarkEditorRegistration =
        registrations.stream()
            .filter(registered -> registered.toadlet() instanceof BookmarkEditorToadlet)
            .findFirst()
            .orElseThrow();
    BookmarkEditorToadletRuntimePorts bookmarkRuntimePorts =
        (BookmarkEditorToadletRuntimePorts)
            readField(bookmarkEditorRegistration.toadlet(), "runtimePorts");
    assertSame(darknetConnectionsPort, bookmarkRuntimePorts.darknetConnectionsPort());
    assertSame(darknetMessagingPort, bookmarkRuntimePorts.darknetMessagingPort());
    verify(runtimePorts, atLeastOnce()).firstTimeWizard();
  }

  @Test
  void maybeCreateFProxyEtc_whenSecurityLevelsSubconfigPresent_skipsSecurityLevelsConfigToadlet() {
    FProxyRegistrar.maybeCreateFProxyEtc(
        dependencies(new LegacyFProxyBrowseRouteRegistrar(client)), server);

    Set<String> configToadletPrefixes =
        capturedRegistrations().stream()
            .filter(registered -> registered.toadlet() instanceof ConfigToadlet)
            .map(registered -> registered.registration().urlPrefix())
            .collect(Collectors.toSet());

    assertEquals(
        Set.of(LegacyHttpPaths.CONFIG_PATH + "alpha", LegacyHttpPaths.CONFIG_PATH + "node"),
        configToadletPrefixes);
    assertFalse(configToadletPrefixes.contains(LegacyHttpPaths.CONFIG_PATH + "security-levels"));
  }

  @Test
  void maybeCreateFProxyEtc_whenWebShellNotPrimary_hidesWebShellMenuLinkUntilShellRootIsPrimary() {
    when(server.primaryUiRoot())
        .thenReturn(LauncherReadinessInfo.DEFAULT_UI_ROOT, WebShellPaths.SHELL_ROOT);

    FProxyRegistrar.maybeCreateFProxyEtc(
        dependencies(new LegacyFProxyBrowseRouteRegistrar(client)), server);

    ToadletRegistration webShellRegistration =
        capturedRegistrations().stream()
            .filter(
                registered ->
                    registered.toadlet() instanceof WebShellToadlet
                        && WebShellPaths.SHELL_ROOT.equals(registered.registration().urlPrefix()))
            .map(RegisteredToadlet::registration)
            .findFirst()
            .orElseThrow();

    assertFalse(webShellRegistration.callback().isEnabled(null));
    assertTrue(webShellRegistration.callback().isEnabled(null));
  }

  @Test
  void maybeCreateFProxyEtc_whenRegisteringShellCategoryRoots_providesLegacyFallbacks() {
    AtomicReference<String> primaryRoot =
        new AtomicReference<>(LauncherReadinessInfo.DEFAULT_UI_ROOT);
    when(server.primaryUiRoot()).thenAnswer(ignored -> primaryRoot.get());

    FProxyRegistrar.maybeCreateFProxyEtc(
        dependencies(new LegacyFProxyBrowseRouteRegistrar(client)), server);

    LinkEnabledCallback friendsCallback =
        capturedCategoryRootCallback(
            LegacyAdminRetirementRegistry.require("friends").replacementUrl(),
            LegacyHttpCategories.CATEGORY_FRIENDS,
            "FProxyToadlet.categoryTitleFriends",
            LegacyHttpPaths.FRIENDS_PATH);
    LinkEnabledCallback statusCallback =
        capturedCategoryRootCallback(
            WebShellPaths.SHELL_ROOT,
            LegacyHttpCategories.CATEGORY_STATUS,
            "FProxyToadlet.categoryTitleStatus",
            "/alerts/");
    LinkEnabledCallback configCallback =
        capturedCategoryRootCallback(
            LegacyAdminRetirementRegistry.require("config").replacementUrl(),
            LegacyHttpCategories.CATEGORY_CONFIG,
            "FProxyToadlet.categoryTitleConfig",
            SecurityLevelsToadlet.PATH);

    assertFalse(friendsCallback.isEnabled(null));
    assertFalse(statusCallback.isEnabled(null));
    assertFalse(configCallback.isEnabled(null));

    primaryRoot.set(WebShellPaths.SHELL_ROOT);

    assertTrue(friendsCallback.isEnabled(null));
    assertTrue(statusCallback.isEnabled(null));
    assertTrue(configCallback.isEnabled(null));
  }

  @Test
  void maybeCreateFProxyEtc_whenRegisteringQueueCategoryRoot_usesAppOnlyWhenAvailable()
      throws Exception {
    AtomicReference<Boolean> installed = new AtomicReference<>(false);
    InstalledAppSnapshot queueManager = installedApp(AppUiMode.STATIC);
    when(appHost.describe("queue-manager"))
        .thenAnswer(_ -> installed.get() ? Optional.of(queueManager) : Optional.empty());

    FProxyRegistrar.maybeCreateFProxyEtc(
        dependencies(new LegacyFProxyBrowseRouteRegistrar(client)), server);

    CategoryRootCallbacks queueCallbacks = capturedQueueCategoryRootCallbacks();
    ToadletContext ctx = mock(ToadletContext.class);
    ToadletContainer container = mock(ToadletContainer.class);
    when(ctx.getContainer()).thenReturn(container);

    when(ctx.isAllowedFullAccess()).thenReturn(false);
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    installed.set(true);
    assertFalse(queueCallbacks.primaryLinkEnabled().isEnabled(ctx));

    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(container.isFProxyJavascriptEnabled()).thenReturn(false);
    assertFalse(queueCallbacks.primaryLinkEnabled().isEnabled(ctx));

    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    installed.set(false);
    assertFalse(queueCallbacks.primaryLinkEnabled().isEnabled(ctx));

    installed.set(true);
    assertTrue(queueCallbacks.primaryLinkEnabled().isEnabled(ctx));

    InstalledAppSnapshot queueManagerWithoutStaticUi = installedApp(AppUiMode.NONE);
    when(appHost.describe("queue-manager")).thenReturn(Optional.of(queueManagerWithoutStaticUi));
    assertFalse(queueCallbacks.primaryLinkEnabled().isEnabled(ctx));

    when(appHost.describe("queue-manager")).thenThrow(new IOException("boom"));
    assertFalse(queueCallbacks.primaryLinkEnabled().isEnabled(ctx));

    when(ctx.isAllowedFullAccess()).thenReturn(false);
    when(container.publicGatewayMode()).thenReturn(true);
    assertFalse(queueCallbacks.rootLinkEnabled().isEnabled(ctx));

    when(container.publicGatewayMode()).thenReturn(false);
    assertTrue(queueCallbacks.rootLinkEnabled().isEnabled(ctx));

    when(container.publicGatewayMode()).thenReturn(true);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    assertTrue(queueCallbacks.rootLinkEnabled().isEnabled(ctx));
  }

  @Test
  void maybeCreateFProxyEtc_whenRegisteringAppUi_registersHiddenAppsPrefixAtFront() {
    FProxyRegistrar.maybeCreateFProxyEtc(
        dependencies(new LegacyFProxyBrowseRouteRegistrar(client)), server);

    ToadletRegistration appUiRegistration =
        capturedRegistrations().stream()
            .filter(registered -> registered.toadlet() instanceof AppUiToadlet)
            .map(RegisteredToadlet::registration)
            .findFirst()
            .orElseThrow();

    assertEquals("/apps/", appUiRegistration.urlPrefix());
    assertTrue(appUiRegistration.atFront());
    assertTrue(appUiRegistration.fullOnly());
  }

  @Test
  void maybeCreateFProxyEtc_whenUsingConcreteBrowseRegistrar_preservesTailBrowseRouteOrder() {
    FProxyRegistrar.maybeCreateFProxyEtc(
        dependencies(new LegacyFProxyBrowseRouteRegistrar(client)), server);

    List<Class<?>> tailRouteTypes = new ArrayList<>();
    for (RegisteredToadlet registration : capturedRegistrations()) {
      Class<?> toadletType = registration.toadlet().getClass();
      if (isTailRouteType(toadletType)) {
        tailRouteTypes.add(toadletType);
      }
    }

    assertEquals(
        List.of(
            PushDataToadlet.class,
            PushNotificationToadlet.class,
            PushKeepaliveToadlet.class,
            PushFailoverToadlet.class,
            PushTesterToadlet.class,
            PushLeavingToadlet.class,
            ImageCreatorToadlet.class,
            LogWritebackToadlet.class,
            DismissAlertToadlet.class),
        tailRouteTypes);
  }

  @Test
  void maybeCreateFProxyEtc_whenUsingBrowseSeam_preservesHistoricalInsertionPoints() {
    FProxyRegistrar.maybeCreateFProxyEtc(dependencies(browseRouteRegistrar), server);

    ArgumentCaptor<LegacyHttpBrowseRouteRegistrar.Phase> phaseCaptor =
        ArgumentCaptor.forClass(LegacyHttpBrowseRouteRegistrar.Phase.class);
    ArgumentCaptor<LegacyHttpBrowseRouteRegistrarContext> browseContextCaptor =
        ArgumentCaptor.forClass(LegacyHttpBrowseRouteRegistrarContext.class);
    verify(browseRouteRegistrar, times(7))
        .registerRoutes(phaseCaptor.capture(), browseContextCaptor.capture(), same(server));
    assertEquals(
        List.of(
            LegacyHttpBrowseRouteRegistrar.Phase.ROOT_MENU,
            LegacyHttpBrowseRouteRegistrar.Phase.INTRO_ROUTES,
            LegacyHttpBrowseRouteRegistrar.Phase.QUEUE_FILTER_ROUTES,
            LegacyHttpBrowseRouteRegistrar.Phase.POST_CONFIG_ROUTES,
            LegacyHttpBrowseRouteRegistrar.Phase.POST_MESSAGING_ROUTES,
            LegacyHttpBrowseRouteRegistrar.Phase.POST_PLATFORM_API_ROUTES,
            LegacyHttpBrowseRouteRegistrar.Phase.TAIL_ROUTES),
        phaseCaptor.getAllValues());
    for (LegacyHttpBrowseRouteRegistrarContext browseContext : browseContextCaptor.getAllValues()) {
      assertSame(runtimePorts, browseContext.runtimePorts());
      assertSame(browseRoot, browseContext.browseRoot());
    }

    InOrder inOrder = inOrder(server, browseRouteRegistrar);
    inOrder
        .verify(browseRouteRegistrar)
        .registerRoutes(
            eq(LegacyHttpBrowseRouteRegistrar.Phase.ROOT_MENU),
            any(LegacyHttpBrowseRouteRegistrarContext.class),
            same(server));
    inOrder
        .verify(server)
        .registerMenu(
            eq(LegacyAdminRetirementRegistry.require("queue-downloads").replacementUrl()),
            eq(LegacyHttpCategories.CATEGORY_QUEUE),
            eq("FProxyToadlet.categoryTitleQueue"),
            eq(QueueToadlet.PATH_DOWNLOADS),
            eq(false),
            any(LinkEnabledCallback.class),
            any(LinkEnabledCallback.class));
    inOrder
        .verify(browseRouteRegistrar)
        .registerRoutes(
            eq(LegacyHttpBrowseRouteRegistrar.Phase.INTRO_ROUTES),
            any(LegacyHttpBrowseRouteRegistrarContext.class),
            same(server));
    verifyRegistrationInOrder(inOrder, server, UserAlertsToadlet.class, "/alerts/");
    verifyRegistrationInOrder(
        inOrder, server, LocalFileInsertToadlet.class, LocalFileInsertToadlet.INSERT_BROWSE_PATH);
    inOrder
        .verify(browseRouteRegistrar)
        .registerRoutes(
            eq(LegacyHttpBrowseRouteRegistrar.Phase.QUEUE_FILTER_ROUTES),
            any(LegacyHttpBrowseRouteRegistrarContext.class),
            same(server));
    verifyRegistrationInOrder(inOrder, server, SymlinkerToadlet.class, "/sl/");
    inOrder
        .verify(browseRouteRegistrar)
        .registerRoutes(
            eq(LegacyHttpBrowseRouteRegistrar.Phase.POST_CONFIG_ROUTES),
            any(LegacyHttpBrowseRouteRegistrarContext.class),
            same(server));
    verifyRegistrationInOrder(
        inOrder,
        server,
        network.crypta.clients.http.updater.CoreActionToadlet.class,
        CORE_UPDATE_PATH);
    verifyRegistrationInOrder(
        inOrder, server, LocalFileN2NMToadlet.class, LocalFileN2NMToadlet.BROWSE_PATH);
    inOrder
        .verify(browseRouteRegistrar)
        .registerRoutes(
            eq(LegacyHttpBrowseRouteRegistrar.Phase.POST_MESSAGING_ROUTES),
            any(LegacyHttpBrowseRouteRegistrarContext.class),
            same(server));
    verifyRegistrationInOrder(inOrder, server, WebShellToadlet.class, WebShellPaths.SHELL_ROOT);
    verifyRegistrationInOrder(inOrder, server, AppUiToadlet.class, "/apps/");
    verifyRegistrationInOrder(
        inOrder, server, PlatformApiToadlet.class, PlatformApiToadlet.MOUNT_PATH);
    inOrder
        .verify(browseRouteRegistrar)
        .registerRoutes(
            eq(LegacyHttpBrowseRouteRegistrar.Phase.POST_PLATFORM_API_ROUTES),
            any(LegacyHttpBrowseRouteRegistrarContext.class),
            same(server));
    verifyRegistrationInOrder(inOrder, server, StatisticsToadlet.class, "/stats/");
    verifyRegistrationInOrder(inOrder, server, SimpleHelpToadlet.class, "/help/");
    inOrder
        .verify(browseRouteRegistrar)
        .registerRoutes(
            eq(LegacyHttpBrowseRouteRegistrar.Phase.TAIL_ROUTES),
            any(LegacyHttpBrowseRouteRegistrarContext.class),
            same(server));
  }

  @Test
  void maybeCreateFProxyEtc_whenPrimaryReplacedRoutesRegistered_hidesLegacyMenuEntries() {
    FProxyRegistrar.maybeCreateFProxyEtc(
        dependencies(new LegacyFProxyBrowseRouteRegistrar(client)), server);

    List<RegisteredToadlet> registrations = capturedRegistrations();

    assertRouteOnlyRegistration(registrations, "/alerts/");
    assertRouteOnlyRegistration(registrations, QueueToadlet.PATH_DOWNLOADS);
    assertRouteOnlyRegistration(registrations, QueueToadlet.PATH_UPLOADS);
    assertRouteOnlyRegistration(registrations, FileInsertWizardToadlet.PATH);
    assertRouteOnlyRegistration(registrations, LocalFileInsertToadlet.INSERT_BROWSE_PATH);
    assertRouteOnlyRegistration(registrations, SecurityLevelsToadlet.PATH);
    assertRouteOnlyRegistration(registrations, LegacyHttpPaths.CONFIG_PATH + "alpha");
    assertRouteOnlyRegistration(registrations, LegacyHttpPaths.CONFIG_PATH + "node");
    assertRouteOnlyRegistration(registrations, CORE_UPDATE_PATH);
    assertRouteOnlyRegistration(registrations, LegacyHttpPaths.FRIENDS_PATH);
    assertRouteOnlyRegistration(registrations, "/addfriend/");
    assertRouteOnlyRegistration(registrations, "/strangers/");
    assertRouteOnlyRegistration(registrations, "/stats/");
    assertRouteOnlyRegistration(registrations, "/diagnostic/");
    assertRouteOnlyRegistration(registrations, ConnectivityToadlet.CONNECTIVITY_PATH);

    assertMenuRegistration(
        registrations, "/chat/", "FProxyToadlet.categoryChat", "FProxyToadlet.chatForumsTitle");
    assertMenuRegistration(
        registrations,
        TranslationToadlet.TOADLET_URL,
        LegacyHttpCategories.CATEGORY_CONFIG,
        "TranslationToadlet.title");
    assertMenuRegistration(
        registrations,
        WebShellPaths.SHELL_ROOT,
        LegacyHttpCategories.CATEGORY_STATUS,
        "FProxyToadlet.webShellTitle");
  }

  @Test
  void registerRoutes_whenInvokedViaLegacyAdminRegistrar_forwardsEquivalentDependencies() {
    LegacyHttpRouteRegistrarContext context =
        new LegacyHttpRouteRegistrarContext(
            runtimePorts,
            appHost,
            config,
            browseRoot,
            browseRouteRegistrar,
            new InsertCompatibilityModes(List.of("COMPAT_DEFAULT"), "COMPAT_DEFAULT"));

    try (MockedStatic<FProxyRegistrar> registrar = mockStatic(FProxyRegistrar.class)) {
      new LegacyAdminHttpRouteRegistrar().registerRoutes(context, server);

      registrar.verify(
          () ->
              FProxyRegistrar.maybeCreateFProxyEtc(
                  new FProxyRegistrarDependencies(
                      runtimePorts,
                      appHost,
                      config,
                      browseRoot,
                      browseRouteRegistrar,
                      new InsertCompatibilityModes(List.of("COMPAT_DEFAULT"), "COMPAT_DEFAULT")),
                  server));
    }
  }

  private FProxyRegistrarDependencies dependencies(
      LegacyHttpBrowseRouteRegistrar browseRouteRegistrar) {
    return new FProxyRegistrarDependencies(
        runtimePorts,
        appHost,
        config,
        browseRoot,
        browseRouteRegistrar,
        new InsertCompatibilityModes(List.of("COMPAT_DEFAULT"), "COMPAT_DEFAULT"));
  }

  private static void registerBandwidthOption(
      SubConfig subConfig, String optionName, int defaultValue) {
    subConfig.register(optionName, defaultValue, optionMeta(), new MemoryIntCallback(defaultValue));
  }

  private static Option.Meta optionMeta() {
    return new Option.Meta(0, false, false, "", "");
  }

  private List<RegisteredToadlet> capturedRegistrations() {
    ArgumentCaptor<Toadlet> toadletCaptor = ArgumentCaptor.forClass(Toadlet.class);
    ArgumentCaptor<ToadletRegistration> registrationCaptor =
        ArgumentCaptor.forClass(ToadletRegistration.class);
    verify(server, atLeastOnce()).register(toadletCaptor.capture(), registrationCaptor.capture());

    List<RegisteredToadlet> registrations = new ArrayList<>();
    List<Toadlet> toadlets = toadletCaptor.getAllValues();
    List<ToadletRegistration> registrationValues = registrationCaptor.getAllValues();
    for (int i = 0; i < toadlets.size(); i++) {
      registrations.add(new RegisteredToadlet(toadlets.get(i), registrationValues.get(i)));
    }
    return registrations;
  }

  private static FirstTimeWizardPort readWizardPortField(Object target) {
    return (FirstTimeWizardPort) readField(target, "wizardPort");
  }

  private static void verifyRegistrationInOrder(
      InOrder inOrder,
      SimpleToadletServer server,
      Class<? extends Toadlet> toadletType,
      String urlPrefix) {
    inOrder
        .verify(server)
        .register(
            argThat(toadletType::isInstance), argThat(reg -> urlPrefix.equals(reg.urlPrefix())));
  }

  private static void assertRouteOnlyRegistration(
      List<RegisteredToadlet> registrations, String urlPrefix) {
    ToadletRegistration registration = registrationFor(registrations, urlPrefix);

    assertNull(registration.menu());
    assertNull(registration.name());
    assertEquals(urlPrefix, registration.urlPrefix());
  }

  private static void assertMenuRegistration(
      List<RegisteredToadlet> registrations, String urlPrefix, String menu, String name) {
    ToadletRegistration registration = registrationFor(registrations, urlPrefix);

    assertEquals(menu, registration.menu());
    assertEquals(name, registration.name());
    assertEquals(urlPrefix, registration.urlPrefix());
  }

  private LinkEnabledCallback capturedCategoryRootCallback(
      String link, String name, String title, String fallbackLink) {
    ArgumentCaptor<LinkEnabledCallback> callbackCaptor =
        ArgumentCaptor.forClass(LinkEnabledCallback.class);
    verify(server)
        .registerMenu(eq(link), eq(name), eq(title), eq(fallbackLink), callbackCaptor.capture());
    return callbackCaptor.getValue();
  }

  private CategoryRootCallbacks capturedQueueCategoryRootCallbacks() {
    ArgumentCaptor<LinkEnabledCallback> primaryCallbackCaptor =
        ArgumentCaptor.forClass(LinkEnabledCallback.class);
    ArgumentCaptor<LinkEnabledCallback> rootCallbackCaptor =
        ArgumentCaptor.forClass(LinkEnabledCallback.class);
    verify(server)
        .registerMenu(
            eq(LegacyAdminRetirementRegistry.require("queue-downloads").replacementUrl()),
            eq(LegacyHttpCategories.CATEGORY_QUEUE),
            eq("FProxyToadlet.categoryTitleQueue"),
            eq(QueueToadlet.PATH_DOWNLOADS),
            eq(false),
            primaryCallbackCaptor.capture(),
            rootCallbackCaptor.capture());
    return new CategoryRootCallbacks(
        primaryCallbackCaptor.getValue(), rootCallbackCaptor.getValue());
  }

  private record CategoryRootCallbacks(
      LinkEnabledCallback primaryLinkEnabled, LinkEnabledCallback rootLinkEnabled) {}

  private static InstalledAppSnapshot installedApp(AppUiMode uiMode) {
    InstalledAppSnapshot snapshot = mock(InstalledAppSnapshot.class);
    AppManifest manifest = mock(AppManifest.class);
    when(snapshot.manifest()).thenReturn(manifest);
    when(manifest.uiMode()).thenReturn(uiMode);
    return snapshot;
  }

  private static ToadletRegistration registrationFor(
      List<RegisteredToadlet> registrations, String urlPrefix) {
    return registrations.stream()
        .map(RegisteredToadlet::registration)
        .filter(registration -> urlPrefix.equals(registration.urlPrefix()))
        .findFirst()
        .orElseThrow();
  }

  private static boolean isTailRouteType(Class<?> toadletType) {
    return toadletType == PushDataToadlet.class
        || toadletType == PushNotificationToadlet.class
        || toadletType == PushKeepaliveToadlet.class
        || toadletType == PushFailoverToadlet.class
        || toadletType == PushTesterToadlet.class
        || toadletType == PushLeavingToadlet.class
        || toadletType == ImageCreatorToadlet.class
        || toadletType == LogWritebackToadlet.class
        || toadletType == DismissAlertToadlet.class;
  }

  private static Object readField(Object target, String fieldName) {
    try {
      java.lang.reflect.Field field = target.getClass().getDeclaredField(fieldName);
      field.setAccessible(true);
      return field.get(target);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final class MemoryIntCallback extends IntCallback {
    private int value;

    private MemoryIntCallback(int value) {
      this.value = value;
    }

    @Override
    public Integer get() {
      return value;
    }

    @Override
    public void set(Integer value) {
      this.value = value;
    }
  }

  private record RegisteredToadlet(Toadlet toadlet, ToadletRegistration registration) {}
}
