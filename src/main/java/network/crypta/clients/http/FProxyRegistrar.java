package network.crypta.clients.http;

import java.util.Arrays;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.ajaxpush.DismissAlertToadlet;
import network.crypta.clients.http.ajaxpush.LogWritebackToadlet;
import network.crypta.clients.http.ajaxpush.PushDataToadlet;
import network.crypta.clients.http.ajaxpush.PushFailoverToadlet;
import network.crypta.clients.http.ajaxpush.PushKeepaliveToadlet;
import network.crypta.clients.http.ajaxpush.PushLeavingToadlet;
import network.crypta.clients.http.ajaxpush.PushNotificationToadlet;
import network.crypta.clients.http.ajaxpush.PushTesterToadlet;
import network.crypta.clients.http.wizardsteps.BandwidthLimit;
import network.crypta.clients.http.wizardsteps.DatastoreSize;
import network.crypta.config.Config;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.RequestStarter;
import network.crypta.node.updater.CoreActionToadlet;
import network.crypta.runtime.spi.RuntimePorts;

import static network.crypta.node.updater.UpdaterPaths.CORE_UPDATE_PATH;

/**
 * Registers every FProxy-facing toadlet and menu entry exposed by the Crypta node.
 *
 * <p>This helper centralizes the wiring of the HTTP user interface: it constructs shared
 * client-side helpers, instantiates each toadlet, assigns menu categories, and publishes them on
 * the {@link SimpleToadletServer}. Callers invoke it once during node startup to ensure all public
 * endpoints—browsing, queue management, configuration, alerts, and update actions—are available
 * before handling requests. The registrar is intentionally package-private and stateless; it relies
 * on the provided {@link NodeClientCore}, {@link Node}, and {@link Config} instances for runtime
 * settings and threat posture.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Creating a shared {@link HighLevelSimpleClient} and fetch tracker used by toadlets.
 *   <li>Registering navigation menus under canonical categories for consistent UI grouping.
 *   <li>Instantiating functional toadlets for downloads, uploads, security, chat, stats,
 *       connectivity, first-time wizard flows, and core updates.
 * </ul>
 *
 * <p>Thread-safety: registration is expected to run on a single startup thread; no internal state
 * is retained after setup. Mutability is limited to injecting constructed toadlets into the server.
 */
final class FProxyRegistrar {

  private FProxyRegistrar() {}

  /**
   * Builds and registers the full FProxy toadlet set if the environment supports it.
   *
   * <p>The method seeds shared randomness, prepares a high-level client with interactive priority,
   * wires a {@link FProxyFetchTracker}, and then registers every relevant toadlet with the provided
   * server. Registration order aligns with menu placement: browsing first, followed by queue
   * handlers, configuration, status/alerts, chat, and maintenance endpoints. This method must be
   * called exactly once during startup; it performs no deduplication and assumes the server is
   * empty.
   *
   * @param core node client core supplying security levels, download directories, and RNG access;
   *     must be initialized and non-null.
   * @param node running node instance providing transport and runtime data; never null.
   * @param config composite configuration used to enumerate sub-configs for dynamic toadlets.
   * @param server toadlet server that exposes HTTP endpoints; expected to be in registration phase.
   */
  static void maybeCreateFProxyEtc(
      NodeClientCore core, Node node, Config config, SimpleToadletServer server) {

    HighLevelSimpleClient client =
        core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true);
    RuntimePorts runtimePorts = core.getRuntimePorts();

    FProxyToadlet.random = new byte[32];
    core.getRandom().nextBytes(FProxyToadlet.random);

    FProxyFetchTracker fetchTracker =
        new FProxyFetchTracker(
            core.getClientContext(),
            client.getFetchContext(),
            new RequestClientBuilder().realTime().build());

    FProxyToadlet fproxy = new FProxyToadlet(client, core, fetchTracker);
    core.getEndpoints().setFProxy(fproxy);

    server.registerMenu(
        "/", FProxyToadlet.CATEGORY_BROWSING, "FProxyToadlet.categoryTitleBrowsing");
    server.registerMenu(
        FProxyToadlet.DOWNLOADS_PATH,
        FProxyToadlet.CATEGORY_QUEUE,
        "FProxyToadlet.categoryTitleQueue");
    server.registerMenu(
        FProxyToadlet.FRIENDS_PATH,
        FProxyToadlet.CATEGORY_FRIENDS,
        "FProxyToadlet.categoryTitleFriends");
    server.registerMenu("/chat/", "FProxyToadlet.categoryChat", "FProxyToadlet.categoryTitleChat");
    server.registerMenu(
        "/alerts/", FProxyToadlet.CATEGORY_STATUS, "FProxyToadlet.categoryTitleStatus");
    server.registerMenu(
        "/seclevels/", FProxyToadlet.CATEGORY_CONFIG, "FProxyToadlet.categoryTitleConfig");

    server.register(
        fproxy,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_BROWSING,
            "/",
            false,
            "FProxyToadlet.welcomeTitle",
            "FProxyToadlet.welcome",
            false,
            null));

    DecodeToadlet decodeKeywordURL = new DecodeToadlet(client, core);
    server.register(decodeKeywordURL, ToadletRegistration.basic(null, "/decode/", true, false));

    InsertFreesiteToadlet siteinsert = new InsertFreesiteToadlet(client);
    server.register(
        siteinsert,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_BROWSING,
            "/insertsite/",
            true,
            "FProxyToadlet.insertFreesiteTitle",
            "FProxyToadlet.insertFreesite",
            false,
            null));

    UserAlertsToadlet alerts = new UserAlertsToadlet(client);
    server.register(
        alerts,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_STATUS,
            "/alerts/",
            true,
            "FProxyToadlet.alertsTitle",
            "FProxyToadlet.alerts",
            true,
            null));

    QueueToadlet downloadToadlet =
        new QueueToadlet(
            client,
            false,
            new QueueToadletRuntimePorts(
                runtimePorts.queuePage(),
                runtimePorts.transferAccess(),
                runtimePorts.queueDownload(),
                runtimePorts.queueInsert(),
                runtimePorts.queueMutation(),
                runtimePorts.queueSupport(),
                runtimePorts.queueCompletion(),
                runtimePorts.darknetConnections(),
                runtimePorts.darknetMessaging()));
    server.register(
        downloadToadlet,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_QUEUE,
            QueueToadlet.PATH_DOWNLOADS,
            true,
            "FProxyToadlet.downloadsTitle",
            "FProxyToadlet.downloads",
            false,
            downloadToadlet));
    LocalDownloadDirectoryToadlet localDownloadDirectoryToadlet =
        new LocalDownloadDirectoryToadlet(core, client, QueueToadlet.PATH_DOWNLOADS);
    server.register(
        localDownloadDirectoryToadlet,
        ToadletRegistration.basic(null, localDownloadDirectoryToadlet.path(), true, false));
    QueueToadlet uploadToadlet =
        new QueueToadlet(
            client,
            true,
            new QueueToadletRuntimePorts(
                runtimePorts.queuePage(),
                runtimePorts.transferAccess(),
                runtimePorts.queueDownload(),
                runtimePorts.queueInsert(),
                runtimePorts.queueMutation(),
                runtimePorts.queueSupport(),
                runtimePorts.queueCompletion(),
                runtimePorts.darknetConnections(),
                runtimePorts.darknetMessaging()));
    server.register(
        uploadToadlet,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_QUEUE,
            QueueToadlet.PATH_UPLOADS,
            true,
            "FProxyToadlet.uploadsTitle",
            "FProxyToadlet.uploads",
            false,
            uploadToadlet));

    FileInsertWizardToadlet fiw = new FileInsertWizardToadlet(client, core);
    server.register(
        fiw,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_QUEUE,
            FileInsertWizardToadlet.PATH,
            true,
            "FProxyToadlet.uploadFileWizardTitle",
            "FProxyToadlet.uploadFileWizard",
            false,
            fiw));
    uploadToadlet.setFIW(fiw);

    LocalFileInsertToadlet localFileInsertToadlet = new LocalFileInsertToadlet(core, client);
    server.register(
        localFileInsertToadlet,
        ToadletRegistration.basic(null, LocalFileInsertToadlet.INSERT_BROWSE_PATH, true, false));

    ContentFilterToadlet contentFilterToadlet = new ContentFilterToadlet(client, core);
    server.register(
        contentFilterToadlet,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_QUEUE,
            ContentFilterToadlet.CONTENT_FILTER_PATH,
            true,
            "FProxyToadlet.filterFileTitle",
            "FProxyToadlet.filterFile",
            false,
            contentFilterToadlet));

    LocalFileFilterToadlet localFileFilterToadlet = new LocalFileFilterToadlet(core, client);
    server.register(
        localFileFilterToadlet,
        ToadletRegistration.basic(null, LocalFileFilterToadlet.BROWSE_PATH, true, false));

    SymlinkerToadlet symlinkToadlet = new SymlinkerToadlet(client, node);
    server.register(symlinkToadlet, ToadletRegistration.basic(null, "/sl/", true, false));

    SecurityLevelsToadletRuntimePorts securityLevelsToadletRuntimePorts =
        new SecurityLevelsToadletRuntimePorts(runtimePorts.securityLevels(), runtimePorts.config());
    SecurityLevelsToadlet seclevels =
        new SecurityLevelsToadlet(client, securityLevelsToadletRuntimePorts);
    server.register(
        seclevels,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_CONFIG,
            "/seclevels/",
            true,
            "FProxyToadlet.seclevelsTitle",
            "FProxyToadlet.seclevels",
            true,
            null));

    ConfigToadletRuntimePorts configToadletRuntimePorts =
        new ConfigToadletRuntimePorts(
            runtimePorts.config(), runtimePorts.transferAccess(), runtimePorts.lifecycle());
    SubConfig[] sc = config.getConfigs();
    Arrays.sort(sc);

    for (SubConfig cfg : sc) {
      String prefix = cfg.getPrefix();
      if (prefix.equals("security-levels")) continue;
      LocalDirectoryConfigToadlet localDirectoryConfigToadlet =
          new LocalDirectoryConfigToadlet(core, client, FProxyToadlet.CONFIG_PATH + prefix);
      ConfigToadlet configtoadlet =
          new ConfigToadlet(
              localDirectoryConfigToadlet.path(), client, config, cfg, configToadletRuntimePorts);
      server.register(
          configtoadlet,
          ToadletRegistration.menuLink(
              FProxyToadlet.CATEGORY_CONFIG,
              FProxyToadlet.CONFIG_PATH + prefix,
              true,
              "ConfigToadlet." + prefix,
              "ConfigToadlet.title." + prefix,
              true,
              configtoadlet));
      server.register(
          localDirectoryConfigToadlet,
          ToadletRegistration.basic(null, localDirectoryConfigToadlet.path(), true, false));
    }

    WelcomeToadletRuntimePorts welcomeToadletRuntimePorts =
        new WelcomeToadletRuntimePorts(
            runtimePorts.welcomePage(),
            runtimePorts.darknetConnections(),
            runtimePorts.lifecycle());
    WelcomeToadlet welcometoadlet = new WelcomeToadlet(client, node, welcomeToadletRuntimePorts);
    server.register(
        welcometoadlet, ToadletRegistration.basic(null, FProxyToadlet.WELCOME_PATH, true, false));

    ExternalLinkToadlet externalLinkToadlet = new ExternalLinkToadlet(client, node);
    server.register(
        externalLinkToadlet,
        ToadletRegistration.basic(null, ExternalLinkToadlet.EXTERNAL_LINK_PATH, true, false));

    CoreActionToadlet coreActionToadlet = new CoreActionToadlet(client, node);
    server.register(
        coreActionToadlet, ToadletRegistration.basic(null, CORE_UPDATE_PATH, true, false));

    ConnectionsToadletRuntimePorts connectionsToadletRuntimePorts =
        new ConnectionsToadletRuntimePorts(
            runtimePorts.connectionsPage(),
            runtimePorts.peer(),
            runtimePorts.nodeInfo(),
            runtimePorts.config(),
            runtimePorts.connectionsSupport());

    DarknetConnectionsToadlet friendsToadlet =
        new DarknetConnectionsToadlet(
            client, connectionsToadletRuntimePorts, runtimePorts.darknetConnections());
    server.register(
        friendsToadlet,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_FRIENDS,
            FProxyToadlet.FRIENDS_PATH,
            true,
            "FProxyToadlet.friendsTitle",
            "FProxyToadlet.friends",
            true,
            null));

    DarknetAddRefToadlet addRefToadlet =
        new DarknetAddRefToadlet(
            runtimePorts.connectionsSupport(), runtimePorts.nodeInfo(), client, friendsToadlet);
    server.register(
        addRefToadlet,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_FRIENDS,
            "/addfriend/",
            true,
            "FProxyToadlet.addFriendTitle",
            "FProxyToadlet.addFriend",
            true,
            null));

    OpennetConnectionsToadlet opennetToadlet =
        new OpennetConnectionsToadlet(client, connectionsToadletRuntimePorts);
    server.register(
        opennetToadlet,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_STATUS,
            "/strangers/",
            true,
            "FProxyToadlet.opennetTitle",
            "FProxyToadlet.opennet",
            true,
            opennetToadlet));

    ChatForumsToadlet chatForumsToadlet = new ChatForumsToadlet(client);
    server.register(
        chatForumsToadlet,
        ToadletRegistration.menuLink(
            "FProxyToadlet.categoryChat",
            "/chat/",
            true,
            "FProxyToadlet.chatForumsTitle",
            "FProxyToadlet.chatForums",
            true,
            chatForumsToadlet));

    LocalFileN2NMToadlet localFileN2NMToadlet = new LocalFileN2NMToadlet(core, client);
    N2NTMToadlet n2ntmToadlet = new N2NTMToadlet(runtimePorts, localFileN2NMToadlet, client);
    server.register(n2ntmToadlet, ToadletRegistration.basic(null, "/send_n2ntm/", true, true));
    server.register(
        localFileN2NMToadlet,
        ToadletRegistration.basic(null, LocalFileN2NMToadlet.BROWSE_PATH, true, false));

    BookmarkEditorToadlet bookmarkEditorToadlet = new BookmarkEditorToadlet(client, core);
    server.register(
        bookmarkEditorToadlet, ToadletRegistration.basic(null, "/bookmarkEditor/", true, false));

    BrowserTestToadlet browserTestToadlet = new BrowserTestToadlet(client);
    server.register(browserTestToadlet, ToadletRegistration.basic(null, "/test/", true, false));

    StatisticsToadlet statisticsToadlet = new StatisticsToadlet(client, runtimePorts.statistics());
    server.register(
        statisticsToadlet,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_STATUS,
            "/stats/",
            true,
            "FProxyToadlet.statsTitle",
            "FProxyToadlet.stats",
            true,
            null));

    DiagnosticToadlet diagnosticToadlet = new DiagnosticToadlet(client, runtimePorts.diagnostic());
    server.register(
        diagnosticToadlet,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_STATUS,
            "/diagnostic/",
            true,
            "FProxyToadlet.diagnosticTitle",
            "FProxyToadlet.diagnostic",
            true,
            null));

    ConnectivityToadlet connectivityToadlet =
        new ConnectivityToadlet(client, runtimePorts.connectivity());
    server.register(
        connectivityToadlet,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_STATUS,
            "/connectivity/",
            true,
            "ConnectivityToadlet.connectivityTitle",
            "ConnectivityToadlet.connectivity",
            true,
            null));

    TranslationToadlet translationToadlet = new TranslationToadlet(client);
    server.register(
        translationToadlet,
        ToadletRegistration.menuLink(
            FProxyToadlet.CATEGORY_CONFIG,
            TranslationToadlet.TOADLET_URL,
            true,
            "TranslationToadlet.title",
            "TranslationToadlet.titleLong",
            true,
            null));

    FirstTimeWizardToadlet firstTimeWizardToadlet =
        new FirstTimeWizardToadlet(
            client,
            config,
            new FirstTimeWizardToadletRuntimePorts(
                runtimePorts.firstTimeWizard(),
                () -> DatastoreSize.maxDatastoreSize(node),
                () -> legacyCurrentBandwidthLimits(config, node)));
    server.register(
        firstTimeWizardToadlet,
        ToadletRegistration.basic(null, FirstTimeWizardToadlet.TOADLET_URL, true, false));

    FirstTimeWizardNewToadlet firstTimeWizardNewToadlet =
        new FirstTimeWizardNewToadlet(client, runtimePorts.firstTimeWizard());
    server.register(
        firstTimeWizardNewToadlet,
        ToadletRegistration.basic(null, FirstTimeWizardNewToadlet.TOADLET_URL, true, false));

    SimpleHelpToadlet simpleHelpToadlet = new SimpleHelpToadlet(client, core);
    server.register(simpleHelpToadlet, ToadletRegistration.basic(null, "/help/", true, false));

    PushDataToadlet pushDataToadlet = new PushDataToadlet(client);
    server.register(
        pushDataToadlet, ToadletRegistration.basic(null, pushDataToadlet.path(), true, false));

    PushNotificationToadlet pushNotificationToadlet = new PushNotificationToadlet(client);
    server.register(
        pushNotificationToadlet,
        ToadletRegistration.basic(null, pushNotificationToadlet.path(), true, false));

    PushKeepaliveToadlet pushKeepaliveToadlet = new PushKeepaliveToadlet(client);
    server.register(
        pushKeepaliveToadlet,
        ToadletRegistration.basic(null, pushKeepaliveToadlet.path(), true, false));

    PushFailoverToadlet pushFailoverToadlet = new PushFailoverToadlet(client);
    server.register(
        pushFailoverToadlet,
        ToadletRegistration.basic(null, pushFailoverToadlet.path(), true, false));

    PushTesterToadlet pushTesterToadlet = new PushTesterToadlet(client);
    server.register(
        pushTesterToadlet, ToadletRegistration.basic(null, pushTesterToadlet.path(), true, false));

    PushLeavingToadlet pushLeavingToadlet = new PushLeavingToadlet(client);
    server.register(
        pushLeavingToadlet,
        ToadletRegistration.basic(null, pushLeavingToadlet.path(), true, false));

    ImageCreatorToadlet imageCreatorToadlet = new ImageCreatorToadlet(client);
    server.register(
        imageCreatorToadlet,
        ToadletRegistration.basic(null, imageCreatorToadlet.path(), true, false));

    LogWritebackToadlet logWritebackToadlet = new LogWritebackToadlet(client);
    server.register(
        logWritebackToadlet,
        ToadletRegistration.basic(null, logWritebackToadlet.path(), true, false));

    DismissAlertToadlet dismissAlertToadlet = new DismissAlertToadlet(client);
    server.register(
        dismissAlertToadlet,
        ToadletRegistration.basic(null, dismissAlertToadlet.path(), true, false));
  }

  private static BandwidthLimit legacyCurrentBandwidthLimits(Config config, Node node) {
    if (config.get("node").getOption("outputBandwidthLimit").isDefault()) {
      return null;
    }

    return new BandwidthLimit(
        node.network().inputBandwidthLimit(),
        node.network().outputBandwidthLimit(),
        "bandwidthCurrent",
        false);
  }
}
