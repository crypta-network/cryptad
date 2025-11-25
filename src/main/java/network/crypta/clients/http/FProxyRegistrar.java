package network.crypta.clients.http;

import static network.crypta.node.updater.UpdaterPathsKt.CORE_UPDATE_PATH;

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
import network.crypta.config.Config;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.RequestStarter;
import network.crypta.node.updater.CoreActionToadlet;

/**
 * Registers every FProxy-facing toadlet and menu entry exposed by the Crypta node.
 *
 * <p>This helper centralizes the wiring of the HTTP user interface: it constructs shared
 * client-side helpers, instantiates each toadlet, assigns menu categories, and publishes them on
 * the {@link SimpleToadletServer}. Callers invoke it once during node startup to ensure all public
 * endpoints—browsing, queue management, configuration, alerts, and update actions—are available
 * before handling requests. The registrar is intentionally package-private and stateless; it relies
 * on the provided {@link NodeClientCore}, {@link Node}, and {@link Config} instances for runtime
 * settings, threat posture, and plugin availability.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Creating a shared {@link HighLevelSimpleClient} and fetch tracker used by toadlets.
 *   <li>Registering navigation menus under canonical categories for consistent UI grouping.
 *   <li>Instantiating functional toadlets for downloads, uploads, security, plugins, chat, stats,
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
   * handlers, configuration, status/alerts, chat, and maintenance endpoints. Plugin-backed toadlets
   * are added conditionally based on the node’s plugin manager. This method must be called exactly
   * once during startup; it performs no deduplication and assumes the server is empty.
   *
   * @param core node client core supplying security levels, download directories, and RNG access;
   *     must be initialized and non-null.
   * @param node running node instance providing plugin manager and transport data; never null.
   * @param config composite configuration used to enumerate sub-configs for dynamic toadlets.
   * @param server toadlet server that exposes HTTP endpoints; expected to be in registration phase.
   */
  static void maybeCreateFProxyEtc(
      NodeClientCore core, Node node, Config config, SimpleToadletServer server) {

    HighLevelSimpleClient client =
        core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true);

    FProxyToadlet.random = new byte[32];
    core.getRandom().nextBytes(FProxyToadlet.random);

    FProxyFetchTracker fetchTracker =
        new FProxyFetchTracker(
            core.getClientContext(),
            client.getFetchContext(),
            new RequestClientBuilder().realTime().build());

    FProxyToadlet fproxy = new FProxyToadlet(client, core, fetchTracker);
    core.setFProxy(fproxy);

    server.registerMenu(
        "/", FProxyToadlet.CATEGORY_BROWSING, "FProxyToadlet.categoryTitleBrowsing", null);
    server.registerMenu(
        FProxyToadlet.DOWNLOADS_PATH,
        FProxyToadlet.CATEGORY_QUEUE,
        "FProxyToadlet.categoryTitleQueue",
        null);
    server.registerMenu(
        FProxyToadlet.FRIENDS_PATH,
        FProxyToadlet.CATEGORY_FRIENDS,
        "FProxyToadlet.categoryTitleFriends",
        null);
    server.registerMenu(
        "/chat/", "FProxyToadlet.categoryChat", "FProxyToadlet.categoryTitleChat", null);
    server.registerMenu(
        "/alerts/", FProxyToadlet.CATEGORY_STATUS, "FProxyToadlet.categoryTitleStatus", null);
    server.registerMenu(
        "/seclevels/", FProxyToadlet.CATEGORY_CONFIG, "FProxyToadlet.categoryTitleConfig", null);

    server.register(
        fproxy,
        FProxyToadlet.CATEGORY_BROWSING,
        "/",
        false,
        "FProxyToadlet.welcomeTitle",
        "FProxyToadlet.welcome",
        false,
        null);

    DecodeToadlet decodeKeywordURL = new DecodeToadlet(client, core);
    server.register(decodeKeywordURL, null, "/decode/", true, false);

    InsertFreesiteToadlet siteinsert = new InsertFreesiteToadlet(client);
    server.register(
        siteinsert,
        FProxyToadlet.CATEGORY_BROWSING,
        "/insertsite/",
        true,
        "FProxyToadlet.insertFreesiteTitle",
        "FProxyToadlet.insertFreesite",
        false,
        null);

    UserAlertsToadlet alerts = new UserAlertsToadlet(client);
    server.register(
        alerts,
        FProxyToadlet.CATEGORY_STATUS,
        "/alerts/",
        true,
        "FProxyToadlet.alertsTitle",
        "FProxyToadlet.alerts",
        true,
        null);

    QueueToadlet downloadToadlet = new QueueToadlet(core, core.getFCPServer(), client, false);
    server.register(
        downloadToadlet,
        FProxyToadlet.CATEGORY_QUEUE,
        FProxyToadlet.DOWNLOADS_PATH,
        true,
        "FProxyToadlet.downloadsTitle",
        "FProxyToadlet.downloads",
        false,
        downloadToadlet);
    LocalDownloadDirectoryToadlet localDownloadDirectoryToadlet =
        new LocalDownloadDirectoryToadlet(core, client, FProxyToadlet.DOWNLOADS_PATH);
    server.register(
        localDownloadDirectoryToadlet, null, localDownloadDirectoryToadlet.path(), true, false);
    QueueToadlet uploadToadlet = new QueueToadlet(core, core.getFCPServer(), client, true);
    server.register(
        uploadToadlet,
        FProxyToadlet.CATEGORY_QUEUE,
        "/uploads/",
        true,
        "FProxyToadlet.uploadsTitle",
        "FProxyToadlet.uploads",
        false,
        uploadToadlet);

    FileInsertWizardToadlet fiw = new FileInsertWizardToadlet(client, core);
    server.register(
        fiw,
        FProxyToadlet.CATEGORY_QUEUE,
        FileInsertWizardToadlet.PATH,
        true,
        "FProxyToadlet.uploadFileWizardTitle",
        "FProxyToadlet.uploadFileWizard",
        false,
        fiw);
    uploadToadlet.setFIW(fiw);

    LocalFileInsertToadlet localFileInsertToadlet = new LocalFileInsertToadlet(core, client);
    server.register(localFileInsertToadlet, null, LocalFileInsertToadlet.PATH, true, false);

    ContentFilterToadlet contentFilterToadlet = new ContentFilterToadlet(client, core);
    server.register(
        contentFilterToadlet,
        FProxyToadlet.CATEGORY_QUEUE,
        ContentFilterToadlet.CONTENT_FILTER_PATH,
        true,
        "FProxyToadlet.filterFileTitle",
        "FProxyToadlet.filterFile",
        false,
        contentFilterToadlet);

    LocalFileFilterToadlet localFileFilterToadlet = new LocalFileFilterToadlet(core, client);
    server.register(localFileFilterToadlet, null, LocalFileFilterToadlet.PATH, true, false);

    SymlinkerToadlet symlinkToadlet = new SymlinkerToadlet(client, node);
    server.register(symlinkToadlet, null, "/sl/", true, false);

    SecurityLevelsToadlet seclevels = new SecurityLevelsToadlet(client, node, core);
    server.register(
        seclevels,
        FProxyToadlet.CATEGORY_CONFIG,
        "/seclevels/",
        true,
        "FProxyToadlet.seclevelsTitle",
        "FProxyToadlet.seclevels",
        true,
        null);

    if (node.getPluginManager().isEnabled()) {
      PproxyToadlet pproxy = new PproxyToadlet(client, node);
      server.register(
          pproxy,
          FProxyToadlet.CATEGORY_CONFIG,
          "/plugins/",
          true,
          "FProxyToadlet.pluginsTitle",
          "FProxyToadlet.plugins",
          true,
          null);
    }

    SubConfig[] sc = config.getConfigs();
    Arrays.sort(sc);

    for (SubConfig cfg : sc) {
      String prefix = cfg.getPrefix();
      if (prefix.equals("security-levels") || prefix.equals("pluginmanager")) continue;
      LocalDirectoryConfigToadlet localDirectoryConfigToadlet =
          new LocalDirectoryConfigToadlet(core, client, FProxyToadlet.CONFIG_PATH + prefix);
      ConfigToadlet configtoadlet =
          new ConfigToadlet(localDirectoryConfigToadlet.path(), client, config, cfg, node, core);
      server.register(
          configtoadlet,
          FProxyToadlet.CATEGORY_CONFIG,
          FProxyToadlet.CONFIG_PATH + prefix,
          true,
          "ConfigToadlet." + prefix,
          "ConfigToadlet.title." + prefix,
          true,
          configtoadlet);
      server.register(
          localDirectoryConfigToadlet, null, localDirectoryConfigToadlet.path(), true, false);
    }

    WelcomeToadlet welcometoadlet = new WelcomeToadlet(client, node);
    server.register(welcometoadlet, null, FProxyToadlet.WELCOME_PATH, true, false);

    ExternalLinkToadlet externalLinkToadlet = new ExternalLinkToadlet(client, node);
    server.register(externalLinkToadlet, null, ExternalLinkToadlet.EXTERNAL_LINK_PATH, true, false);

    CoreActionToadlet coreActionToadlet = new CoreActionToadlet(client, node);
    server.register(coreActionToadlet, null, CORE_UPDATE_PATH, true, false);

    DarknetConnectionsToadlet friendsToadlet = new DarknetConnectionsToadlet(node, core, client);
    server.register(
        friendsToadlet,
        FProxyToadlet.CATEGORY_FRIENDS,
        FProxyToadlet.FRIENDS_PATH,
        true,
        "FProxyToadlet.friendsTitle",
        "FProxyToadlet.friends",
        true,
        null);

    DarknetAddRefToadlet addRefToadlet = new DarknetAddRefToadlet(node, client, friendsToadlet);
    server.register(
        addRefToadlet,
        FProxyToadlet.CATEGORY_FRIENDS,
        "/addfriend/",
        true,
        "FProxyToadlet.addFriendTitle",
        "FProxyToadlet.addFriend",
        true,
        null);

    OpennetConnectionsToadlet opennetToadlet = new OpennetConnectionsToadlet(node, core, client);
    server.register(
        opennetToadlet,
        FProxyToadlet.CATEGORY_STATUS,
        "/strangers/",
        true,
        "FProxyToadlet.opennetTitle",
        "FProxyToadlet.opennet",
        true,
        opennetToadlet);

    ChatForumsToadlet chatForumsToadlet = new ChatForumsToadlet(client, node.getPluginManager());
    server.register(
        chatForumsToadlet,
        "FProxyToadlet.categoryChat",
        "/chat/",
        true,
        "FProxyToadlet.chatForumsTitle",
        "FProxyToadlet.chatForums",
        true,
        chatForumsToadlet);

    N2NTMToadlet n2ntmToadlet = new N2NTMToadlet(node, core, client, "/friends/");
    server.register(n2ntmToadlet, null, "/send_n2ntm/", true, true);
    LocalFileN2NMToadlet localFileN2NMToadlet = new LocalFileN2NMToadlet(core, client);
    server.register(localFileN2NMToadlet, null, LocalFileN2NMToadlet.BROWSE_PATH, true, false);

    BookmarkEditorToadlet bookmarkEditorToadlet = new BookmarkEditorToadlet(client, core);
    server.register(bookmarkEditorToadlet, null, "/bookmarkEditor/", true, false);

    BrowserTestToadlet browserTestToadlet = new BrowserTestToadlet(client);
    server.register(browserTestToadlet, null, "/test/", true, false);

    StatisticsToadlet statisticsToadlet = new StatisticsToadlet(node, core, client);
    server.register(
        statisticsToadlet,
        FProxyToadlet.CATEGORY_STATUS,
        "/stats/",
        true,
        "FProxyToadlet.statsTitle",
        "FProxyToadlet.stats",
        true,
        null);

    DiagnosticToadlet diagnosticToadlet = new DiagnosticToadlet(node, core.getFCPServer(), client);
    server.register(
        diagnosticToadlet,
        FProxyToadlet.CATEGORY_STATUS,
        "/diagnostic/",
        true,
        "FProxyToadlet.diagnosticTitle",
        "FProxyToadlet.diagnostic",
        true,
        null);

    ConnectivityToadlet connectivityToadlet = new ConnectivityToadlet(client, node);
    server.register(
        connectivityToadlet,
        FProxyToadlet.CATEGORY_STATUS,
        "/connectivity/",
        true,
        "ConnectivityToadlet.connectivityTitle",
        "ConnectivityToadlet.connectivity",
        true,
        null);

    TranslationToadlet translationToadlet = new TranslationToadlet(client, core);
    server.register(
        translationToadlet,
        FProxyToadlet.CATEGORY_CONFIG,
        TranslationToadlet.TOADLET_URL,
        true,
        "TranslationToadlet.title",
        "TranslationToadlet.titleLong",
        true,
        null);

    FirstTimeWizardToadlet firstTimeWizardToadlet = new FirstTimeWizardToadlet(client, node, core);
    server.register(firstTimeWizardToadlet, null, FirstTimeWizardToadlet.TOADLET_URL, true, false);

    FirstTimeWizardNewToadlet firstTimeWizardNewToadlet =
        new FirstTimeWizardNewToadlet(client, core, config);
    server.register(
        firstTimeWizardNewToadlet, null, FirstTimeWizardNewToadlet.TOADLET_URL, true, false);

    SimpleHelpToadlet simpleHelpToadlet = new SimpleHelpToadlet(client, core);
    server.register(simpleHelpToadlet, null, "/help/", true, false);

    PushDataToadlet pushDataToadlet = new PushDataToadlet(client);
    server.register(pushDataToadlet, null, pushDataToadlet.path(), true, false);

    PushNotificationToadlet pushNotificationToadlet = new PushNotificationToadlet(client);
    server.register(pushNotificationToadlet, null, pushNotificationToadlet.path(), true, false);

    PushKeepaliveToadlet pushKeepaliveToadlet = new PushKeepaliveToadlet(client);
    server.register(pushKeepaliveToadlet, null, pushKeepaliveToadlet.path(), true, false);

    PushFailoverToadlet pushFailoverToadlet = new PushFailoverToadlet(client);
    server.register(pushFailoverToadlet, null, pushFailoverToadlet.path(), true, false);

    PushTesterToadlet pushTesterToadlet = new PushTesterToadlet(client);
    server.register(pushTesterToadlet, null, pushTesterToadlet.path(), true, false);

    PushLeavingToadlet pushLeavingToadlet = new PushLeavingToadlet(client);
    server.register(pushLeavingToadlet, null, pushLeavingToadlet.path(), true, false);

    ImageCreatorToadlet imageCreatorToadlet = new ImageCreatorToadlet(client);
    server.register(imageCreatorToadlet, null, imageCreatorToadlet.path(), true, false);

    LogWritebackToadlet logWritebackToadlet = new LogWritebackToadlet(client);
    server.register(logWritebackToadlet, null, logWritebackToadlet.path(), true, false);

    DismissAlertToadlet dismissAlertToadlet = new DismissAlertToadlet(client);
    server.register(dismissAlertToadlet, null, dismissAlertToadlet.path(), true, false);
  }
}
