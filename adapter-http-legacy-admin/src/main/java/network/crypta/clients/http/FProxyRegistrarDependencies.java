package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.config.Config;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.apphost.AppHost;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Narrow dependency bundle used internally by the admin-owned HTTP registrar.
 *
 * <p>{@link LegacyAdminHttpRouteRegistrar} adapts the public shell-local route-registration seam to
 * the existing {@link FProxyRegistrar} helper by assembling this package-private dependency bundle.
 * The registrar can therefore stay focused on HTTP concerns such as menu registration, toadlet
 * registration, and wiring already-created helpers into those routes. This record exists only to
 * keep that adaptation explicit and local to the HTTP package.
 *
 * <p>The type is intentionally package-private. It is not a general runtime abstraction and does
 * not try to hide broader node relationships. It simply groups the collaborators that the registrar
 * actually consumes so startup composition remains in one place while HTTP registration remains
 * deterministic and easy to test.
 *
 * @param runtimePorts detached runtime ports exposed to the HTTP shell
 * @param appHost shared AppHost instance exposed through the Platform API bridge
 * @param appCatalogManager optional signed app-catalog manager exposed through the Platform API
 * @param config node configuration used to list sub-config toadlets
 * @param browseRoot prebuilt root browse toadlet handed to the registrar for root-path registration
 * @param browseRouteRegistrar browse-neutral registrar seam used for browse-owned route publication
 * @param insertCompatibilityModes detached compatibility-mode choices used by queue and insert
 *     forms
 */
record FProxyRegistrarDependencies(
    RuntimePorts runtimePorts,
    AppHost appHost,
    AppCatalogManager appCatalogManager,
    Config config,
    Toadlet browseRoot,
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar,
    InsertCompatibilityModes insertCompatibilityModes) {
  /**
   * Creates a dependency bundle for embeddings without signed app-catalog support.
   *
   * @param runtimePorts runtime-spi ports exposed to HTTP-layer toadlets and helper pages
   * @param appHost shared AppHost instance exposed through the Platform API bridge
   * @param config node configuration used to list and filter sub-config toadlets
   * @param browseRoot prebuilt root browse toadlet that is registered at the HTTP root path
   * @param browseRouteRegistrar browse-neutral registrar seam used for browse-owned route
   *     publication
   * @param insertCompatibilityModes detached compatibility-mode choices used by queue and insert
   *     forms
   */
  FProxyRegistrarDependencies(
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
        config,
        browseRoot,
        browseRouteRegistrar,
        insertCompatibilityModes);
  }

  /**
   * Creates a validated dependency bundle for {@link FProxyRegistrar}.
   *
   * <p>All collaborators are required because registration is an all-or-nothing startup step. The
   * constructor rejects the partially assembled state early, so the caller fails to close to the
   * HTTP shell composition site rather than later during menu or toadlet registration.
   *
   * @param runtimePorts runtime-spi ports exposed to HTTP-layer toadlets and helper pages
   * @param appHost shared AppHost instance exposed through the Platform API bridge
   * @param appCatalogManager optional signed app-catalog manager exposed through the Platform API
   * @param config node configuration used to list and filter sub-config toadlets
   * @param browseRoot prebuilt root browse toadlet that is registered at the HTTP root path
   * @param browseRouteRegistrar browse-neutral registrar seam used for browse-owned route
   *     publication
   * @param insertCompatibilityModes detached compatibility-mode choices used by queue and insert
   *     forms
   * @throws NullPointerException if any required collaborator is absent at construction time
   */
  FProxyRegistrarDependencies {
    Objects.requireNonNull(runtimePorts);
    Objects.requireNonNull(appHost);
    Objects.requireNonNull(config);
    Objects.requireNonNull(browseRoot);
    Objects.requireNonNull(browseRouteRegistrar);
    Objects.requireNonNull(insertCompatibilityModes);
  }

  LegacyHttpBrowseRouteRegistrarContext browseContext() {
    return new LegacyHttpBrowseRouteRegistrarContext(runtimePorts, browseRoot);
  }
}
