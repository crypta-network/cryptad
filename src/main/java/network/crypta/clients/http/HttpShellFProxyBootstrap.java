package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.bookmark.BookmarkManager;

/**
 * Bundles the daemon-built collaborators that the HTTP shell needs after root FProxy bootstrap.
 *
 * <p>{@link SimpleToadletServer} creates the root FProxy stack only once and then reuses the
 * resulting collaborators when it registers child toadlets and bookmark-dependent views. This
 * record keeps that handoff explicit and minimal: the bookmark manager carries the daemon-backed
 * bookmark runtime, the interactive client is shared by HTTP toadlets, and the root {@link
 * FProxyToadlet} is returned directly to the shell bootstrap path for registration.
 *
 * <p>This record is public only, so runtime-owned HTTP bootstrap adapters can construct and return
 * the bundle from outside {@code network.crypta.clients.http}. It is not a new platform API.
 *
 * @param bookmarkManager bookmark manager wired against the daemon-backed bookmark runtime support
 * @param client interactive client shared by HTTP toadlets created during shell startup
 * @param fproxy root FProxy toadlet constructed during bootstrap and handed to the registrar flow
 */
public record HttpShellFProxyBootstrap(
    BookmarkManager bookmarkManager, HighLevelSimpleClient client, FProxyToadlet fproxy) {

  /**
   * Creates the bundle while keeping {@link FProxyToadlet}'s constructor package-owned.
   *
   * <p>Runtime-owned HTTP bootstrap glue calls this factory when it needs the package-local toadlet
   * instantiation behavior without widening {@link FProxyToadlet} itself.
   *
   * @param bookmarkManager bookmark manager used by the surrounding shell bootstrap
   * @param client interactive client shared by FProxy and sibling toadlets
   * @param runtimeSupport FProxy runtime adapter used by the root toadlet
   * @param fetchTracker fetch tracker shared by root FProxy request handling
   * @return bootstrap bundle containing the constructed root FProxy toadlet
   */
  public static HttpShellFProxyBootstrap create(
      BookmarkManager bookmarkManager,
      HighLevelSimpleClient client,
      FProxyRuntimeSupport runtimeSupport,
      FProxyFetchTracker fetchTracker) {
    return new HttpShellFProxyBootstrap(
        bookmarkManager, client, new FProxyToadlet(client, runtimeSupport, fetchTracker));
  }

  /**
   * Validates that every required bootstrap collaborator is present.
   *
   * @throws NullPointerException if any bootstrap collaborator is {@code null}
   */
  public HttpShellFProxyBootstrap {
    Objects.requireNonNull(bookmarkManager);
    Objects.requireNonNull(client);
    Objects.requireNonNull(fproxy);
  }
}
