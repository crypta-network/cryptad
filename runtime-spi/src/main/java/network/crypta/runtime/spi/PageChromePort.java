package network.crypta.runtime.spi;

/**
 * Exposes the narrow detached runtime state needed by the shared admin page chrome.
 *
 * <p>This SPI exists only for the legacy HTTP shell that still needs a few live daemon reads to
 * render the status bar. The HTTP layer keeps ownership of alerts, menus, mode switching,
 * localization, and HTML structure; implementations provide only a detached snapshot containing the
 * current security posture and peer-count progress values.
 *
 * <p>The contract is intentionally read-only and page-shell-specific. It should not grow into a
 * general admin API or absorb unrelated browse, queue, or FCP concerns. Callers typically treat
 * this port as optional startup wiring: if the shell has not been connected to a runtime yet, the
 * page can still render safely without a status bar.
 *
 * @see PageChromeSnapshot
 */
public interface PageChromePort {
  /**
   * Returns a detached snapshot of the current page-chrome state.
   *
   * <p>Callers typically read one snapshot near the start of page rendering and use it for the rest
   * of that request so the status bar stays internally consistent even if the live daemon state
   * changes moments later. Implementations may gather that data from several live services, but the
   * returned record itself is immutable and side-effect-free for the caller.
   *
   * @return immutable snapshot containing the current security-level and peer-progress state
   */
  PageChromeSnapshot snapshot();
}
