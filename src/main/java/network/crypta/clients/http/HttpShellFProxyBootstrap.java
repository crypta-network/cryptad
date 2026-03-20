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
 * FProxyToadlet} has already been published to client endpoints by the time the shell receives this
 * bundle.
 *
 * @param bookmarkManager bookmark manager wired against the daemon-backed bookmark runtime support
 * @param client interactive client shared by HTTP toadlets created during shell startup
 * @param fproxy root FProxy toadlet that has already been connected to daemon client endpoints
 */
record HttpShellFProxyBootstrap(
    BookmarkManager bookmarkManager, HighLevelSimpleClient client, FProxyToadlet fproxy) {

  /**
   * Validates that every required bootstrap collaborator is present.
   *
   * @throws NullPointerException if any bootstrap collaborator is {@code null}
   */
  HttpShellFProxyBootstrap {
    Objects.requireNonNull(bookmarkManager);
    Objects.requireNonNull(client);
    Objects.requireNonNull(fproxy);
  }
}
