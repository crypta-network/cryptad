package network.crypta.clients.http;

/**
 * Strategy interface for attaching the concrete legacy HTTP route set to a prepared shell.
 *
 * <p>{@link SimpleToadletServer} performs the shared bootstrap work that both browse-facing and
 * admin-facing HTTP code depend on, but it should not know which concrete registrar owns the
 * remaining route wiring. This seam keeps that ownership outside the shell. Production bridge
 * wiring currently installs {@link LegacyAdminHttpRouteRegistrar}, while focused tests can inject a
 * lightweight fake that records the prepared bootstrap context without instantiating the full HTTP
 * surface.
 *
 * <p>Implementations are expected to treat registration as a one-shot startup operation for a
 * single shell instance. They should preserve the established route order, avoid retaining the
 * provided context after startup, and limit themselves to publishing menus, toadlets, and related
 * shell-local wiring.
 */
@FunctionalInterface
public interface LegacyHttpRouteRegistrar {

  /**
   * Registers the legacy HTTP routes for the supplied shell instance.
   *
   * <p>The supplied context contains the collaborators that the registrar may already need today:
   * the shared interactive client, runtime ports, AppHost bridge, node configuration, and the
   * prebuilt root FProxy toadlet. Implementations should use those values to complete their own
   * startup wiring without re-fetching the broader daemon state from elsewhere. Callers invoke this
   * method during the FProxy bootstrap path before request handling begins.
   *
   * @param context prepared bootstrap collaborators that registration may publish into routes and
   *     helper pages
   * @param server shell instance that should receive the registered menus, toadlets, and related
   *     startup wiring
   */
  void registerRoutes(LegacyHttpRouteRegistrarContext context, SimpleToadletServer server);
}
