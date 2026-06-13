package network.crypta.clients.http;

/**
 * Adapts the shell-local route-registration seam to the current admin-owned HTTP registrar.
 *
 * <p>The shared legacy HTTP shell now depends on {@link LegacyHttpRouteRegistrar} instead of
 * calling {@link FProxyRegistrar} directly. This concrete adapter keeps the existing registrar
 * helper and its dependency bundle on the admin side of the boundary while still preserving the
 * historical startup behavior. Production bridge wiring installs this type during shell creation,
 * and tests may substitute a narrower fake registrar when they only need to observe delegation.
 *
 * <p>The adapter is intentionally stateless. It does not cache the bootstrap state, track
 * registration progress, or change route order. Its only job is to translate the public {@link
 * LegacyHttpRouteRegistrarContext} into the package-private dependency bundle expected by {@link
 * FProxyRegistrar}, then hand control to that existing implementation.
 */
public final class LegacyAdminHttpRouteRegistrar implements LegacyHttpRouteRegistrar {
  /**
   * Creates a stateless registrar adapter for production or test bridge wiring.
   *
   * <p>Instances carry no mutable startup state, so callers may create them as needed without
   * coordinating shared ownership. The explicit constructor exists, so this public type has
   * complete Javadoc coverage under doclint.
   */
  public LegacyAdminHttpRouteRegistrar() {
    // This adapter is intentionally stateless; construction needs no additional work.
  }

  /**
   * Registers the concrete legacy HTTP routes for the supplied shell instance.
   *
   * <p>The provided context already contains the runtime ports, configuration, AppHost bridge,
   * browse-root toadlet, browse registrar seam, and detached insert compatibility choices prepared
   * by the shared shell bootstrap path. Repackaging those collaborators here keeps the public seam
   * small while letting the existing admin-owned registrar continue to own the overall registration
   * order.
   *
   * @param context prepared bootstrap collaborators that the admin-owned registrar requires
   * @param server shell instance that receives the registered menus and toadlets
   */
  @Override
  public void registerRoutes(LegacyHttpRouteRegistrarContext context, SimpleToadletServer server) {
    FProxyRegistrar.maybeCreateFProxyEtc(
        new FProxyRegistrarDependencies(
            context.runtimePorts(),
            context.appHost(),
            context.appCatalogManager(),
            context.appUpdateService(),
            context.contentSubscriptionService(),
            context.appDataService(),
            context.trustGraphApiHandler(),
            context.appServiceCoordinator(),
            context.appNetworkBudgetService(),
            context.appVaultService(),
            context.config(),
            context.browseRoot(),
            context.browseRouteRegistrar(),
            context.insertCompatibilityModes()),
        server);
  }
}
