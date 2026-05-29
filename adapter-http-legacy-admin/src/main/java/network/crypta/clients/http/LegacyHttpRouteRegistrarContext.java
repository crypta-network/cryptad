package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.config.Config;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appservices.AppServiceCoordinator;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Immutable bootstrap context handed from the shared shell to a concrete route registrar.
 *
 * <p>{@link SimpleToadletServer#createFproxy()} assembles the shared collaborators that route
 * registration still needs after the shell finishes its common startup work. This record packages
 * those values into one small handoff object so the shell does not expose a wider bootstrap API
 * just to support registrar-specific wiring. The type is public because bridge-owned production
 * code installs registrar implementations from outside this package, but its contents stay focused
 * on route registration rather than broader daemon lifecycle control.
 *
 * <p>The context is intentionally narrow and immutable. It carries only the collaborators needed to
 * publish legacy HTTP routes today: detached runtime ports, AppHost bridge, node configuration, and
 * the already-created browse root. Registrars should treat the record as a startup snapshot and
 * avoid mutating or retaining it beyond registration.
 *
 * @param runtimePorts detached runtime-spi ports surfaced to HTTP routes and helper pages
 * @param appHost shared AppHost bridge that exposes the current Platform API runtime surface
 * @param appCatalogManager optional signed app-catalog manager for catalog Platform API routes
 * @param appUpdateService optional app-update service shared with background scheduling
 * @param contentSubscriptionService optional content subscription service shared with background
 *     scheduling
 * @param appDataService optional durable app-data service shared with Platform API routes
 * @param trustGraphApiHandler optional durable trust graph handler shared with Platform API routes
 * @param appServiceCoordinator optional app-service coordinator shared with Platform API routes
 * @param appVaultService optional app-vault service for vault Platform API routes
 * @param config node configuration view used when listing or filtering sub-config toadlets
 * @param browseRoot prebuilt root browse toadlet that anchors the registration pass at the legacy
 *     browsing root
 * @param browseRouteRegistrar browse-neutral registrar seam used for concrete browse-owned route
 *     publication
 * @param insertCompatibilityModes detached compatibility-mode choices used by queue and insert
 *     forms
 */
public record LegacyHttpRouteRegistrarContext(
    RuntimePorts runtimePorts,
    AppHost appHost,
    AppCatalogManager appCatalogManager,
    AppUpdateService appUpdateService,
    ContentSubscriptionService contentSubscriptionService,
    AppDataService appDataService,
    TrustGraphApiHandler trustGraphApiHandler,
    AppServiceCoordinator appServiceCoordinator,
    AppVaultService appVaultService,
    Config config,
    Toadlet browseRoot,
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar,
    InsertCompatibilityModes insertCompatibilityModes) {

  /**
   * Creates a context for embeddings that have not configured signed app catalogs.
   *
   * @param runtimePorts detached runtime-spi ports exposed to the HTTP registrar
   * @param appHost shared AppHost bridge made visible through HTTP-owned routes
   * @param config node configuration view that registration may inspect for sub-config pages
   * @param browseRoot prebuilt root browse toadlet registered at the browsing root
   * @param browseRouteRegistrar browse-neutral registrar seam used for browse-owned route
   *     publication
   * @param insertCompatibilityModes detached compatibility-mode choices used by queue and insert
   *     forms
   */
  public LegacyHttpRouteRegistrarContext(
      RuntimePorts runtimePorts,
      AppHost appHost,
      Config config,
      Toadlet browseRoot,
      LegacyHttpBrowseRouteRegistrar browseRouteRegistrar,
      InsertCompatibilityModes insertCompatibilityModes) {
    this(
        runtimePorts,
        appHost,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        config,
        browseRoot,
        browseRouteRegistrar,
        insertCompatibilityModes);
  }

  /**
   * Creates a validated route-registration context.
   *
   * <p>Registration is an all-or-nothing startup step, so the constructor rejects the partially
   * assembled state immediately instead of letting a registrar fail later while building menus or
   * toadlets. The stored references are the same objects prepared by the shell bootstrap path; the
   * constructor does not wrap, copy, or otherwise transform them.
   *
   * @param runtimePorts detached runtime-spi ports exposed to the HTTP registrar
   * @param appHost shared AppHost bridge made visible through HTTP-owned routes
   * @param appCatalogManager optional signed app-catalog manager for catalog Platform API routes
   * @param appUpdateService optional app-update service shared with background scheduling
   * @param contentSubscriptionService optional content subscription service shared with background
   *     scheduling
   * @param appDataService optional durable app-data service shared with Platform API routes
   * @param trustGraphApiHandler optional durable trust graph handler shared with Platform API
   *     routes
   * @param appServiceCoordinator optional app-service coordinator shared with Platform API routes
   * @param appVaultService optional app-vault service for vault Platform API routes
   * @param config node configuration view that registration may inspect for sub-config pages
   * @param browseRoot prebuilt root browse toadlet registered at the browsing root
   * @param browseRouteRegistrar browse-neutral registrar seam used for browse-owned route
   *     publication
   * @param insertCompatibilityModes detached compatibility-mode choices used by queue and insert
   *     forms
   * @throws NullPointerException if any required collaborator is absent when the context is built
   */
  public LegacyHttpRouteRegistrarContext {
    Objects.requireNonNull(runtimePorts);
    Objects.requireNonNull(appHost);
    Objects.requireNonNull(config);
    Objects.requireNonNull(browseRoot);
    Objects.requireNonNull(browseRouteRegistrar);
    Objects.requireNonNull(insertCompatibilityModes);
  }
}
