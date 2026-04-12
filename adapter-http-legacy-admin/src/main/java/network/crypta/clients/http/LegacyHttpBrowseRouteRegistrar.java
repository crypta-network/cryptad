package network.crypta.clients.http;

/**
 * Browse-neutral seam for publishing browse-owned legacy HTTP routes.
 *
 * <p>The admin-owned legacy HTTP registrar still owns the overall startup orchestration and must
 * preserve the historical registration order. It should not directly instantiate the concrete
 * browse/FProxy route families that will move out during the future physical browse split. This
 * seam lets the admin-owned orchestration invoke browse-owned publication at the exact existing
 * insertion points. It also keeps shared-shell and admin bootstrap code free from concrete
 * browse-route classes, which makes the eventual module extraction mostly mechanical instead of a
 * second behavior-changing refactor.
 *
 * <p>Implementations are expected to treat registration as a one-shot startup action for a single
 * {@link SimpleToadletServer}. They should publish only the browse-owned routes assigned to the
 * requested {@link Phase}, avoid retaining the provided context after startup, and preserve the
 * current route and menu ordering established by the admin-owned orchestrator. The seam is narrow
 * by design: it is not a general plugin system for arbitrary HTTP features. It exists only to
 * separate browse-owned route construction from the still-admin-owned legacy startup flow.
 */
public interface LegacyHttpBrowseRouteRegistrar {

  /**
   * Fixed browse-owned insertion points in the historical legacy HTTP registration order.
   *
   * <p>The admin-owned registrar invokes these phases in order while registering the remaining
   * admin-owned routes in between. Concrete browse registrars must publish only the routes assigned
   * to the requested phase so behavior, route order, and menu visibility remain unchanged.
   */
  enum Phase {
    /** Registers the browsing menu bucket itself before any browse-owned toadlets are published. */
    ROOT_MENU,

    /**
     * Registers the initial browse surface near the root, including the browse root and early
     * helper routes.
     */
    INTRO_ROUTES,

    /**
     * Registers browse-adjacent queue filter routes after the admin-owned queue routes have been
     * published.
     */
    QUEUE_FILTER_ROUTES,

    /** Registers browse-owned routes that historically appeared after the config toadlet block. */
    POST_CONFIG_ROUTES,

    /**
     * Registers browse-owned messaging and bookmark routes after the admin-owned messaging pages.
     */
    POST_MESSAGING_ROUTES,

    /** Registers browse-owned browser-test routes after the platform API and Web Shell entries. */
    POST_PLATFORM_API_ROUTES,

    /** Registers the remaining browse-owned tail routes at the end of legacy HTTP startup. */
    TAIL_ROUTES
  }

  /**
   * Publishes the browse-owned routes assigned to one insertion point.
   *
   * <p>Callers should invoke this only during startup and only in the historical phase order.
   * Implementations should assume the surrounding admin registrar remains responsible for all
   * admin-owned routes, menu categories, and any interleaving between browse-owned phases.
   *
   * @param phase historical registration point whose browse-owned routes should be published
   * @param context browse-local startup collaborators needed to build browse-owned routes
   * @param server shell instance that receives the published browse routes and menu entries
   */
  void registerRoutes(
      Phase phase, LegacyHttpBrowseRouteRegistrarContext context, SimpleToadletServer server);
}
