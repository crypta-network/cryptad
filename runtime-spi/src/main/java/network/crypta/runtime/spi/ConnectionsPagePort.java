package network.crypta.runtime.spi;

/**
 * Exposes the narrow legacy connections-page capability needed by the admin HTTP endpoints.
 *
 * <p>This port is intentionally page-oriented and transitional. The legacy friends and strangers
 * pages still mix large read-only peer traversals with HTML-shaped rendering, while request-context
 * form generation remains in the HTTP layer. Callers therefore request one detached page snapshot
 * per render rather than a reusable peer-management API or a monolithic full-page HTML blob.
 *
 * <p>The port is read-only. It does not perform access control, does not model POST mutations, and
 * does not expose daemon-only types such as {@code Node}, {@code NodeClientCore}, {@code
 * PeerNodeStatus}, {@code HTMLNode}, or {@code ToadletContext}. Implementations may traverse the
 * live daemon state while producing one snapshot, but callers receive only immutable JDK-only DTOs
 * that are safe to retain for the lifetime of one request.
 *
 * @see ConnectionsPageRequest
 * @see ConnectionsPageSnapshot
 */
public interface ConnectionsPagePort {
  /**
   * Returns one detached snapshot of the requested legacy connections page.
   *
   * <p>The returned snapshot preserves the current page-oriented structure: outer content before
   * the peer table, the peer table fragment itself, and any trailing content after the table. The
   * HTTP layer remains responsible for request-context-only behavior such as alert summaries and
   * form wrapping.
   *
   * @param request detached render request describing the page kind and active view flags
   * @return immutable connections-page snapshot for the requested render
   */
  ConnectionsPageSnapshot render(ConnectionsPageRequest request);
}
