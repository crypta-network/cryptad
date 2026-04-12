package network.crypta.clients.http;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.ajaxpush.DismissAlertToadlet;
import network.crypta.clients.http.ajaxpush.LogWritebackToadlet;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.TransferAccessPort;

/**
 * Concrete browse-owned legacy HTTP route registrar used by the current FProxy-backed shell.
 *
 * <p>This implementation stays in {@code :adapter-http-legacy-admin} for now so the physical
 * browse-module move can remain a later mechanical PR. Its job is deliberately small: instantiate
 * the browse/FProxy-owned routes that still live in this package tree today and publish them only
 * when the admin-owned orchestrator asks for the matching registration phase. That keeps concrete
 * browse classes out of the admin-owned startup path while preserving the exact historical
 * insertion points that the legacy shell already exposed.
 *
 * <p>The registrar is stateless and safe to reuse across startup attempts as long as callers still
 * treat registration as a one-shot action for a single {@link SimpleToadletServer}. It does not
 * create menus or routes eagerly. Instead, it reacts to the requested {@link Phase}, publishes only
 * the browse-owned routes assigned to that phase, and leaves the surrounding admin registrar
 * responsible for the overall route order. The AJAX-push route family is delegated to {@link
 * LegacyFProxyAjaxPushRouteRegistrar} so this class can focus on the larger browse ownership seam.
 */
public final class LegacyFProxyBrowseRouteRegistrar implements LegacyHttpBrowseRouteRegistrar {
  private static final LegacyFProxyAjaxPushRouteRegistrar AJAX_PUSH_ROUTE_REGISTRAR =
      new LegacyFProxyAjaxPushRouteRegistrar();

  /**
   * Creates a stateless browse-route registrar for the current FProxy-backed legacy HTTP shell.
   *
   * <p>Construction performs no route instantiation and does not capture runtime-specific state.
   * All browse-owned collaborators still arrive later through the registration context prepared by
   * the shared shell bootstrap path.
   */
  public LegacyFProxyBrowseRouteRegistrar() {
    // This registrar is intentionally stateless.
  }

  /**
   * Publishes the browse-owned routes assigned to one historical legacy registration phase.
   *
   * <p>Each phase corresponds to a fixed insertion point in the old monolithic FProxy registrar.
   * Callers are expected to invoke the phases in the established order while registering the
   * remaining admin-owned routes in between. This method performs no deduplication and assumes it
   * is running during startup against a server that is still being assembled.
   *
   * @param phase browse-owned insertion point whose routes should be published during this call
   * @param context browse-local collaborators required to instantiate the phase-owned routes
   * @param server shell instance that receives the published browse routes and any browse menu
   *     entries
   */
  @Override
  public void registerRoutes(
      Phase phase, LegacyHttpBrowseRouteRegistrarContext context, SimpleToadletServer server) {
    switch (phase) {
      case ROOT_MENU -> registerRootMenu(server);
      case INTRO_ROUTES -> registerIntroRoutes(context, server);
      case QUEUE_FILTER_ROUTES -> registerQueueFilterRoutes(context, server);
      case POST_CONFIG_ROUTES -> registerPostConfigRoutes(context, server);
      case POST_MESSAGING_ROUTES -> registerPostMessagingRoutes(context, server);
      case POST_PLATFORM_API_ROUTES -> registerPostPlatformApiRoutes(context, server);
      case TAIL_ROUTES -> registerTailRoutes(context.client(), server);
    }
  }

  private static void registerRootMenu(SimpleToadletServer server) {
    server.registerMenu(
        "/", LegacyHttpCategories.CATEGORY_BROWSING, "FProxyToadlet.categoryTitleBrowsing");
  }

  private static void registerIntroRoutes(
      LegacyHttpBrowseRouteRegistrarContext context, SimpleToadletServer server) {
    HighLevelSimpleClient client = context.client();

    server.register(
        context.browseRoot(),
        ToadletRegistration.menuLink(
            LegacyHttpCategories.CATEGORY_BROWSING,
            "/",
            false,
            "FProxyToadlet.welcomeTitle",
            "FProxyToadlet.welcome",
            false,
            null));

    DecodeToadlet decodeKeywordURL = new DecodeToadlet(client);
    server.register(decodeKeywordURL, ToadletRegistration.basic(null, "/decode/", true, false));

    InsertFreesiteToadlet siteinsert = new InsertFreesiteToadlet(client);
    server.register(
        siteinsert,
        ToadletRegistration.menuLink(
            LegacyHttpCategories.CATEGORY_BROWSING,
            "/insertsite/",
            true,
            "FProxyToadlet.insertFreesiteTitle",
            "FProxyToadlet.insertFreesite",
            false,
            null));
  }

  private static void registerQueueFilterRoutes(
      LegacyHttpBrowseRouteRegistrarContext context, SimpleToadletServer server) {
    HighLevelSimpleClient client = context.client();
    TransferAccessPort transferAccess = context.runtimePorts().transferAccess();

    ContentFilterToadlet contentFilterToadlet = new ContentFilterToadlet(client);
    server.register(
        contentFilterToadlet,
        ToadletRegistration.menuLink(
            LegacyHttpCategories.CATEGORY_QUEUE,
            ContentFilterToadlet.CONTENT_FILTER_PATH,
            true,
            "FProxyToadlet.filterFileTitle",
            "FProxyToadlet.filterFile",
            false,
            contentFilterToadlet));

    LocalFileFilterToadlet localFileFilterToadlet =
        new LocalFileFilterToadlet(transferAccess, client);
    server.register(
        localFileFilterToadlet,
        ToadletRegistration.basic(null, LocalFileFilterToadlet.BROWSE_PATH, true, false));
  }

  private static void registerPostConfigRoutes(
      LegacyHttpBrowseRouteRegistrarContext context, SimpleToadletServer server) {
    HighLevelSimpleClient client = context.client();
    RuntimePorts runtimePorts = context.runtimePorts();

    WelcomeToadletRuntimePorts welcomeToadletRuntimePorts =
        new WelcomeToadletRuntimePorts(
            runtimePorts.welcomePage(),
            runtimePorts.darknetConnections(),
            runtimePorts.lifecycle(),
            runtimePorts.welcomeAction());
    WelcomeToadlet welcomeToadlet = new WelcomeToadlet(client, welcomeToadletRuntimePorts);
    server.register(
        welcomeToadlet, ToadletRegistration.basic(null, LegacyHttpPaths.WELCOME_PATH, true, false));

    ExternalLinkToadlet externalLinkToadlet = new ExternalLinkToadlet(client);
    server.register(
        externalLinkToadlet,
        ToadletRegistration.basic(null, ExternalLinkToadlet.EXTERNAL_LINK_PATH, true, false));
  }

  private static void registerPostMessagingRoutes(
      LegacyHttpBrowseRouteRegistrarContext context, SimpleToadletServer server) {
    RuntimePorts runtimePorts = context.runtimePorts();
    BookmarkEditorToadlet bookmarkEditorToadlet =
        new BookmarkEditorToadlet(
            context.client(),
            new BookmarkEditorToadletRuntimePorts(
                runtimePorts.darknetConnections(), runtimePorts.darknetMessaging()));
    server.register(
        bookmarkEditorToadlet, ToadletRegistration.basic(null, "/bookmarkEditor/", true, false));
  }

  private static void registerPostPlatformApiRoutes(
      LegacyHttpBrowseRouteRegistrarContext context, SimpleToadletServer server) {
    BrowserTestToadlet browserTestToadlet = new BrowserTestToadlet(context.client());
    server.register(browserTestToadlet, ToadletRegistration.basic(null, "/test/", true, false));
  }

  private static void registerTailRoutes(HighLevelSimpleClient client, SimpleToadletServer server) {
    AJAX_PUSH_ROUTE_REGISTRAR.registerRoutes(client, server);

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
}
