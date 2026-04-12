package network.crypta.clients.http;

import network.crypta.keys.FreenetURI;

/**
 * Neutral handle for the legacy HTTP shell's bookmark collaborator.
 *
 * <p>This interface gives the shared-shell code a stable type that can cross the current
 * browse/admin boundary without importing the browse-owned bookmark package directly. The shared
 * shell only needs a narrow read-oriented view: it can carry a bookmark collaborator through
 * request and server wiring, and it can ask for the current bookmark targets when rendering
 * shell-owned UI. Richer bookmark editing, persistence, and tree-management behavior stays on the
 * concrete browse side for now.
 *
 * <p>Implementations are free to build the returned URI array from a live state or from a cached
 * snapshot, but callers should treat the result as request-time data rather than a mutable backing
 * collection. This keeps the seam small while preserving the current runtime wiring for the later
 * module split work.
 */
public interface BookmarkManagerHandle {
  /**
   * Returns the bookmark URIs visible to the shared shell.
   *
   * <p>The returned array is the only bookmark-specific data currently required by the shared
   * shell. It is used for legacy rendering and request wiring where the shell needs bookmark
   * targets but does not need access to browse-owned editing or organization APIs.
   *
   * <p>Implementations should return an empty array when no bookmarks are available. Callers should
   * not assume ownership of the returned array beyond the immediate read operation, and they should
   * not rely on array identity remaining stable across calls.
   *
   * @return current bookmark URIs visible to the shared shell or an empty array when none are
   *     stored
   */
  FreenetURI[] getBookmarkURIs();
}
