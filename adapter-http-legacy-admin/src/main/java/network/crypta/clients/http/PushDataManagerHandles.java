package network.crypta.clients.http;

import network.crypta.clients.http.updateableelements.PushDataManager;
import network.crypta.support.Ticker;

/**
 * Factory for the legacy HTTP push-data manager handle.
 *
 * <p>This utility centralizes the one place where shared-shell wiring turns a neutral {@link
 * PushDataManagerHandle} dependency into the current concrete browse-owned implementation. That
 * keeps constructor and bootstrap code in the shared shell free from direct imports of {@link
 * network.crypta.clients.http.updateableelements.PushDataManager} while preserving the existing
 * runtime behavior and object graph.
 *
 * <p>The class is intentionally tiny and stateless. It exists to mark the seam explicitly, not to
 * add lifecycle or caching behavior of its own.
 */
public final class PushDataManagerHandles {

  private PushDataManagerHandles() {}

  /**
   * Creates the concrete push-data manager used by the legacy shell.
   *
   * <p>The returned instance is the current production implementation for the legacy push flow. It
   * is exposed as a neutral handle, so shared-shell code can keep working against the seam while
   * the concrete class remains browse-owned during the split-preparation phase.
   *
   * @param ticker scheduler used by the push manager for keepalive cleanup and related timed work
   * @return concrete legacy push-data manager instance exposed through the shared-shell handle
   */
  public static PushDataManagerHandle create(Ticker ticker) {
    return new PushDataManager(ticker);
  }
}
