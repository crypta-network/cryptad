package network.crypta.runtime.spi;

/**
 * Exposes the narrow legacy statistics-page capability needed by the admin HTTP endpoint.
 *
 * <p>This port is intentionally page-oriented rather than metric-oriented. The legacy {@code
 * /stats/} page is still heavily HTML-shaped and bundles a large read-only operational overview
 * with the requester subpage. Callers therefore request detached page snapshots that already
 * contain the rendered legacy content template, while request-context-only concerns such as alert
 * summaries or form-password-protected controls remain in the HTTP layer.
 *
 * <p>The port is read-only and intentionally transitional. It does not define a reusable platform
 * metrics schema, and it does not expose daemon-only types such as {@code Node}, {@code
 * NodeClientCore}, {@code NodeStats}, {@code HTMLNode}, or {@code ToadletContext}. Implementations
 * may traverse the live daemon state while building one snapshot, but callers should see only
 * immutable JDK-only DTOs that are safe to retain for one request.
 *
 * @see StatisticsPageSnapshot
 */
public interface StatisticsPort {
  /**
   * Returns one detached snapshot of the statistics overview page.
   *
   * <p>The {@code advancedMode} flag preserves the legacy page split between the default operator
   * view and the larger advanced render. Implementations may refresh or gather expensive bandwidth
   * counters before rendering so the snapshot remains aligned with the historical overview page
   * behavior.
   *
   * @param advancedMode whether advanced-only sections should be included in the detached template
   * @return immutable statistics-page snapshot for the overview route
   */
  StatisticsPageSnapshot overview(boolean advancedMode);

  /**
   * Returns one detached snapshot of the requester subpage.
   *
   * <p>This subpage remains part of the legacy statistics area, but it preserves its historical
   * behavior of rendering without the overview page's bandwidth-refresh step.
   *
   * @return immutable statistics-page snapshot for the requester route
   */
  StatisticsPageSnapshot requesters();
}
