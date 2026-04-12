package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.bookmark.BookmarkManager;
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
 * @param bookmarkManager bookmark manager wired against the daemon-backed bookmark runtime support
 *     for the surrounding shell lifecycle
 * @param client interactive client shared by HTTP toadlets created during shell startup and route
 *     registration
 * @param appHost shared AppHost instance used by the Platform API control plane and exposed through
 *     legacy HTTP routes
 * @param browseRoot browse-root toadlet constructed during bootstrap and handed to the registrar
 *     for root-path registration
 */
public record HttpShellBrowseBootstrap(
    BookmarkManager bookmarkManager,
    HighLevelSimpleClient client,
    AppHost appHost,
    Toadlet browseRoot) {
  /**
   * Creates the bundle while keeping the browse-root toadlet constructor package-local.
   *
   * <p>Use this overload when runtime-owned code has already constructed the browse root and only
   * needs the shared shell to carry it across the bootstrap seam. The supplied toadlet instance is
   * retained as-is; this method performs no additional browse-specific initialization beyond the
   * record's null checks.
   *
   * @param bookmarkManager bookmark manager used by the surrounding shell bootstrap to populate
   *     bookmark-backed routes
   * @param client interactive client shared by shell toadlets that are registered during startup
   * @param appHost shared AppHost instance used by the platform control plane and related routes
   * @param browseRoot browse-root toadlet used by route registration at the legacy browsing root
   * @return browse-neutral bootstrap bundle containing the supplied collaborators and browse root
   */
  public static HttpShellBrowseBootstrap create(
      BookmarkManager bookmarkManager,
      HighLevelSimpleClient client,
      AppHost appHost,
      Toadlet browseRoot) {
    return new HttpShellBrowseBootstrap(bookmarkManager, client, appHost, browseRoot);
  }

  /**
   * Creates the bundle while keeping the legacy browse-root construction package-owned.
   *
   * <p>The production bridge still assembles concrete FProxy collaborators today, but this helper
   * keeps that construction detail local to the legacy HTTP package while returning the
   * browse-neutral seam shape. The method constructs the current root {@link FProxyToadlet} and
   * preserves the historical startup relationship between that root toadlet, the interactive
   * client, and the shared fetch tracker. It intentionally does not seed the legacy force-link
   * random state; the shared shell owns that initialization step, so alternative runtime-support
   * implementations receive the same guarantee.
   *
   * @param bookmarkManager bookmark manager used by the surrounding shell bootstrap to populate
   *     bookmark-backed routes
   * @param client interactive client shared by shell toadlets that are registered during startup
   * @param appHost shared AppHost instance used by the platform control plane and related routes
   * @param runtimeSupport legacy browse runtime adapter used by the constructed root toadlet
   * @param fetchTracker fetch tracker shared by root browse request handling and progress state
   * @return browse-neutral bootstrap bundle containing the constructed root browse toadlet
   */
  public static HttpShellBrowseBootstrap create(
      BookmarkManager bookmarkManager,
      HighLevelSimpleClient client,
      AppHost appHost,
      FProxyRuntimeSupport runtimeSupport,
      FProxyFetchTracker fetchTracker) {
    FProxyToadlet browseRoot = new FProxyToadlet(client, runtimeSupport, fetchTracker);
    return new HttpShellBrowseBootstrap(bookmarkManager, client, appHost, browseRoot);
  }

  /**
   * Initializes shared legacy shell state that must be ready before route registration starts.
   *
   * <p>The browse-neutral seam still needs to preserve one legacy behavior: browse roots backed by
   * {@link FProxyToadlet} expect a process-wide force-link seed to be initialized before their
   * routes are used. The shared shell calls this method after it obtains {@link RuntimePorts} and
   * before the registrar publishes routes. For non-FProxy browse roots, the method intentionally
   * does nothing, so alternative implementations can cross the same seam without inheriting a hard
   * dependency on FProxy-specific state.
   *
   * @param runtimePorts shared runtime ports that expose the randomness service used by the legacy
   *     shell bootstrap path
   * @throws NullPointerException if {@code runtimePorts} is {@code null} when initialization is
   *     attempted
   */
  void initializeSharedShellState(RuntimePorts runtimePorts) {
    Objects.requireNonNull(runtimePorts, "runtimePorts");
    if (browseRoot instanceof FProxyToadlet) {
      FProxyToadlet.initializeSharedRandom(runtimePorts.randomness());
    }
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
    Objects.requireNonNull(client);
    Objects.requireNonNull(appHost);
    Objects.requireNonNull(browseRoot);
  }
}
