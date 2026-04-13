package network.crypta.clients.http;

import java.util.Objects;
import java.util.function.Consumer;
import network.crypta.platform.apphost.AppHost;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Immutable browse-neutral bootstrap context handed from the shared shell to route registration.
 *
 * <p>This record packages the collaborators that remain relevant after the legacy HTTP shell
 * finishes its common startup work and before the admin-owned registrar publishes the concrete
 * toadlets. The intent is deliberately narrow: it is a local startup handoff for the legacy HTTP
 * adapter, not a new general-purpose runtime API. Callers create one instance per shell bootstrap
 * pass and then immediately hand it to route-registration code.
 *
 * <p>The important boundary change is that the browse root is exposed as a plain {@link Toadlet}
 * rather than a concrete browse implementation. That keeps the shared shell neutral while still
 * preserving the current registration order, bookmark wiring, and AppHost handoff. The contained
 * collaborators are live runtime objects with shared identity, so the record preserves references
 * rather than copying or wrapping them.
 *
 * @param bookmarkManager bookmark handle wired against the daemon-backed bookmark runtime support
 *     for the surrounding shell lifecycle
 * @param appHost shared AppHost instance used by the Platform API control plane and exposed through
 *     legacy HTTP routes
 * @param browseRoot browse-root toadlet constructed during bootstrap and handed to the registrar
 *     for root-path registration
 * @param browseRouteRegistrar browse-neutral registrar seam that publishes browse-owned routes at
 *     the historical insertion points
 * @param sharedShellInitializer browse-neutral hook for any shell-local initialization that must
 *     run before route registration
 */
public record HttpShellBrowseBootstrap(
    BookmarkManagerHandle bookmarkManager,
    AppHost appHost,
    Toadlet browseRoot,
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar,
    Consumer<RuntimePorts> sharedShellInitializer) {
  /**
   * Creates the bundle while keeping the browse-root toadlet constructor package-local.
   *
   * <p>Use this overload when runtime-owned code has already constructed the browse root and only
   * needs the shared shell to carry it across the bootstrap seam. The supplied toadlet instance is
   * retained as-is; this method performs no additional browse-specific initialization beyond the
   * record's null checks.
   *
   * @param bookmarkManager bookmark handle used by the surrounding shell bootstrap to populate
   *     bookmark-backed routes
   * @param appHost shared AppHost instance used by the platform control plane and related routes
   * @param browseRoot browse-root toadlet used by route registration at the legacy browsing root
   * @param browseRouteRegistrar browse-neutral registrar seam for the browse-owned routes
   * @return browse-neutral bootstrap bundle containing the supplied collaborators and browse root
   */
  public static HttpShellBrowseBootstrap create(
      BookmarkManagerHandle bookmarkManager,
      AppHost appHost,
      Toadlet browseRoot,
      LegacyHttpBrowseRouteRegistrar browseRouteRegistrar) {
    return create(bookmarkManager, appHost, browseRoot, browseRouteRegistrar, _ -> {});
  }

  /**
   * Creates the bundle while keeping the browse-neutral initialization hook package-owned.
   *
   * <p>Runtime-owned code provides the initialization callback when it needs to perform shell-local
   * work before route registration. Shared-shell code simply stores and invokes that callback
   * without needing to know what concrete browse implementation or bootstrap state the bridge
   * assembled. Callers may pass a no-op callback when no additional initialization is required.
   *
   * @param bookmarkManager bookmark handle used by the surrounding shell bootstrap to populate
   *     bookmark-backed routes
   * @param appHost shared AppHost instance used by the platform control plane and related routes
   * @param browseRoot browse-root toadlet used by route registration at the legacy browsing root
   * @param browseRouteRegistrar browse-neutral registrar seam for the browse-owned routes
   * @param sharedShellInitializer browse-neutral hook invoked before route registration starts
   * @return browse-neutral bootstrap bundle containing the supplied collaborators and
   *     initialization hook
   */
  public static HttpShellBrowseBootstrap create(
      BookmarkManagerHandle bookmarkManager,
      AppHost appHost,
      Toadlet browseRoot,
      LegacyHttpBrowseRouteRegistrar browseRouteRegistrar,
      Consumer<RuntimePorts> sharedShellInitializer) {
    return new HttpShellBrowseBootstrap(
        bookmarkManager, appHost, browseRoot, browseRouteRegistrar, sharedShellInitializer);
  }

  /**
   * Initializes shared legacy shell state that must be ready before route registration starts.
   *
   * <p>The shared shell calls this method after it obtains {@link RuntimePorts} and before the
   * registrar publishes routes. The bootstrap object decides whether the hook performs any work;
   * callers do not need to know whether the current browse root is FProxy-backed or no-op.
   *
   * @param runtimePorts shared runtime ports that expose the randomness service used by the legacy
   *     shell bootstrap path
   * @throws NullPointerException if {@code runtimePorts} is {@code null} when initialization is
   *     attempted
   */
  void initializeSharedShellState(RuntimePorts runtimePorts) {
    Objects.requireNonNull(runtimePorts, "runtimePorts");
    sharedShellInitializer.accept(runtimePorts);
  }

  /**
   * Validates that every required bootstrap collaborator is present.
   *
   * <p>Bootstrap is an all-or-nothing startup step, so the compact constructor rejects the
   * partially assembled state immediately instead of letting the shared shell or registrar fail
   * later during route publication.
   *
   * @throws NullPointerException if any bootstrap collaborator is {@code null} at construction time
   */
  public HttpShellBrowseBootstrap {
    Objects.requireNonNull(bookmarkManager);
    Objects.requireNonNull(appHost);
    Objects.requireNonNull(browseRoot);
    Objects.requireNonNull(browseRouteRegistrar);
    Objects.requireNonNull(sharedShellInitializer);
  }
}
