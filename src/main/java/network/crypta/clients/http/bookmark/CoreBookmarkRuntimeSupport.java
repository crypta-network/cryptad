package network.crypta.clients.http.bookmark;

import java.io.File;
import java.util.Objects;
import network.crypta.client.async.USKCallback;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.RequestStarter;

import static java.util.concurrent.TimeUnit.MINUTES;

/**
 * Adapts the legacy {@link NodeClientCore} API to {@link BookmarkRuntimeSupport}.
 *
 * <p>This implementation is the compatibility layer used by the HTTP bookmark subsystem while the
 * surrounding FProxy runtime still originates from {@link NodeClientCore}. It translates
 * bookmark-local operations into the existing node services for user-directory file resolution, USK
 * subscription management, update-priority prefetch, and ticker-backed delayed work. That keeps
 * bookmark loading, update handling, and lazy persistence behavior stable while moving the direct
 * core dependency out of {@link BookmarkManager}.
 *
 * <p>The adapter is intentionally small and keeps only an immutable reference to the supplied node
 * core. It is not a general-purpose node facade. Callers are expected to construct it close to
 * bookmark wiring and share it with bookmark code that needs runtime services.
 *
 * <ul>
 *   <li>Expose the existing bookmark file locations from the node's user directory.
 *   <li>Own the private {@link RequestClient} used for bookmark USK subscriptions.
 *   <li>Reuse the node's update-priority client behavior for edition prefetch.
 *   <li>Delegate delayed store scheduling to the node ticker without exposing ticker APIs.
 * </ul>
 *
 * @see BookmarkManager
 * @see BookmarkRuntimeSupport
 */
public final class CoreBookmarkRuntimeSupport implements BookmarkRuntimeSupport {
  private static final RequestClient BOOKMARK_REQUEST_CLIENT = new RequestClientBuilder().build();
  private static final long PREFETCH_TIMEOUT_MILLIS = MINUTES.toMillis(60);

  private final NodeClientCore core;

  /**
   * Creates runtime support backed by the supplied node core.
   *
   * <p>The supplied core must already expose the normal services used by bookmark HTTP handling:
   * the node user directory, the USK manager, update-priority client creation, and the node ticker.
   * This constructor performs no eager setup beyond null checking; all runtime work is delegated
   * when individual adapter methods are invoked.
   *
   * @param core live node core used to reach bookmark files, USK subscriptions, and ticker jobs
   * @throws NullPointerException if {@code core} is {@code null}
   */
  public CoreBookmarkRuntimeSupport(NodeClientCore core) {
    this.core = Objects.requireNonNull(core);
  }

  /** {@inheritDoc} */
  @Override
  public File bookmarksFile() {
    return core.getNode().userDir().file("bookmarks.dat");
  }

  /** {@inheritDoc} */
  @Override
  public File backupBookmarksFile() {
    return core.getNode().userDir().file("bookmarks.dat.bak");
  }

  /** {@inheritDoc} */
  @Override
  public void prefetchUpdatedEdition(FreenetURI uri, long maxSize) {
    core.makeClient(RequestStarter.UPDATE_PRIORITY_CLASS, false, false)
        .prefetch(
            uri, PREFETCH_TIMEOUT_MILLIS, maxSize, null, RequestStarter.UPDATE_PRIORITY_CLASS);
  }

  /** {@inheritDoc} */
  @Override
  public void subscribeToUsk(USK usk, USKCallback callback) {
    core.getUskManager().subscribe(usk, callback, true, BOOKMARK_REQUEST_CLIENT);
  }

  /** {@inheritDoc} */
  @Override
  public void unsubscribeFromUsk(USK usk, USKCallback callback) {
    core.getUskManager().unsubscribe(usk, callback);
  }

  /** {@inheritDoc} */
  @Override
  public void queueLazyStore(Runnable job, long delayMillis) {
    core.getNode().network().ticker().queueTimedJob(job, delayMillis);
  }
}
