package network.crypta.runtime.spi;

import java.io.IOException;

/**
 * Exposes the narrow detached runtime surface still needed by the welcome page GET/read path.
 *
 * <p>This SPI is intentionally tiny and page-oriented. The HTTP layer still owns the welcome-page
 * route, bookmark tree, template structure, and every POST or action handler. Implementations
 * provide only the read-only runtime state that the GET path cannot derive on its own without
 * reaching back into the live daemon: the fetch-key-box placement flag and the latest node log tail
 * shown by the legacy {@code latestlog} endpoint.
 *
 * <p>Callers typically read {@link #snapshot()} while assembling the main page and call {@link
 * #latestNodeLogTail()} only for the dedicated log endpoint. Keeping those concerns in a small SPI
 * lets the HTTP layer detach from the daemon root module without inventing a broader homepage
 * domain model or pulling POST behavior into this interface.
 *
 * @see WelcomePageSnapshot
 */
public interface WelcomePagePort {
  /**
   * Returns a detached snapshot of the current welcome-page read-only state.
   *
   * <p>The returned value is suitable for one request render and captures the small set of
   * config-backed decisions that the welcome page needs while building its GET response. Callers
   * should treat the snapshot as immutable request data rather than a handle for later daemon
   * interaction.
   *
   * @return immutable snapshot containing the current fetch-key-box placement flag for this read
   *     operation
   */
  WelcomePageSnapshot snapshot();

  /**
   * Reads and returns the current latest node log tail used by the welcome page.
   *
   * <p>Implementations should preserve the existing logger-directory lookup, file preference, and
   * tail truncation semantics of the legacy welcome-page handler. The returned text is intended for
   * direct inclusion in the legacy response body for the {@code latestlog} route, so callers should
   * not assume the entire log file is available or that the selected filename is stable across
   * implementations.
   *
   * @return the current latest node log tail as text, already reduced to the legacy byte window
   * @throws IOException if the selected log file cannot be opened or read during this request
   */
  String latestNodeLogTail() throws IOException;
}
