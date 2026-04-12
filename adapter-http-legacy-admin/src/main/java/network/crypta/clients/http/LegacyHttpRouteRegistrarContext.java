package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.config.Config;
import network.crypta.platform.apphost.AppHost;
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
 * publish legacy HTTP routes today: the interactive client, detached runtime ports, AppHost bridge,
 * node configuration, and the already-created root FProxy toadlet. Registrars should treat the
 * record as a startup snapshot and avoid mutating or retaining it beyond registration.
 *
 * @param client shared interactive client that registered toadlets use for request-adjacent
 *     operations
 * @param runtimePorts detached runtime-spi ports surfaced to HTTP routes and helper pages
 * @param appHost shared AppHost bridge that exposes the current Platform API runtime surface
 * @param config node configuration view used when listing or filtering sub-config toadlets
 * @param fproxy prebuilt root FProxy toadlet that anchors the registration pass at the legacy
 *     browsing root
 */
public record LegacyHttpRouteRegistrarContext(
    HighLevelSimpleClient client,
    RuntimePorts runtimePorts,
    AppHost appHost,
    Config config,
    FProxyToadlet fproxy) {

  /**
   * Creates a validated route-registration context.
   *
   * <p>Registration is an all-or-nothing startup step, so the constructor rejects the partially
   * assembled state immediately instead of letting a registrar fail later while building menus or
   * toadlets. The stored references are the same objects prepared by the shell bootstrap path; the
   * constructor does not wrap, copy, or otherwise transform them.
   *
   * @param client shared interactive client that registered toadlets may call into during startup
   * @param runtimePorts detached runtime-spi ports exposed to the HTTP registrar
   * @param appHost shared AppHost bridge made visible through HTTP-owned routes
   * @param config node configuration view that registration may inspect for sub-config pages
   * @param fproxy prebuilt root FProxy toadlet registered at the browsing root
   * @throws NullPointerException if any required collaborator is absent when the context is built
   */
  public LegacyHttpRouteRegistrarContext {
    Objects.requireNonNull(client);
    Objects.requireNonNull(runtimePorts);
    Objects.requireNonNull(appHost);
    Objects.requireNonNull(config);
    Objects.requireNonNull(fproxy);
  }
}
