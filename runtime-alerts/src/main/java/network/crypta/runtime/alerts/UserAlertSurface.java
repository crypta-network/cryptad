package network.crypta.runtime.alerts;

import network.crypta.support.HTMLNode;

/**
 * Consumer-facing alert surface for legacy HTTP and other UI/admin code, owned by {@code
 * :runtime-alerts}.
 *
 * <p>This interface defines the detached contract that browser-facing and administrative surfaces
 * use to work with node alerts. It is intentionally narrower than the concrete {@code
 * UserAlertManager}: consumers can register alerts, dismiss them by hash, take a snapshot of the
 * current alert set, and request pre-rendered HTML fragments for the existing shared shell. That
 * keeps the UI-side boundary small while allowing runtime-node-owned code to keep the broader
 * lifecycle, feed, and subscriber machinery.
 *
 * <p>Callers should treat implementations as a live runtime service rather than as a passive data
 * holder. The array returned by {@link #getAlerts()} is a snapshot suitable for immediate
 * iteration, while the HTML-producing methods are convenience renderers for the legacy shell and
 * therefore reflect the node's current alert state at call time.
 *
 * <ul>
 *   <li>Registration and dismissal for user-visible alerts.
 *   <li>Snapshot access for shell code that needs to inspect current alerts directly.
 *   <li>HTML helpers retained for the existing legacy HTTP rendering path.
 * </ul>
 */
public interface UserAlertSurface {

  /**
   * Registers a user-facing alert with the active surface.
   *
   * <p>Implementations typically deduplicate and order alerts according to the runtime manager's
   * existing rules. Callers normally invoke this when a new operational condition should become
   * visible in the shared shell or related user-facing status surfaces.
   *
   * @param alert alert instance to add to the active surface so current and future UI renders can
   *     include it
   */
  void register(UserAlert alert);

  /**
   * Dismisses an alert identified by its hash code when that alert allows user dismissal.
   *
   * <p>This method mirrors the legacy HTTP behavior, where dismissal requests travel through form
   * posts that carry an alert hash rather than a direct object reference. Implementations may
   * ignore the request when no matching alert exists or when the matching alert is not dismissible.
   *
   * @param alertHashCode hash code of the alert the caller wants to dismiss from the active surface
   */
  void dismissAlert(int alertHashCode);

  /**
   * Returns a snapshot of the current alerts visible through this surface.
   *
   * <p>The returned array is intended for immediate iteration and rendering. Implementations may
   * sort the snapshot according to the runtime manager's current ordering rules, but callers should
   * not assume the array remains live after the method returns.
   *
   * @return snapshot of the active alerts currently exposed through the detached surface
   */
  UserAlert[] getAlerts();

  /**
   * Renders the current alert set as an HTML fragment for legacy shell pages.
   *
   * <p>This helper preserves the existing HTML-oriented rendering contract used by the old HTTP
   * pages. The returned node is suitable for embedding into a larger page tree and reflects the
   * filtering rules requested by the caller at the time of invocation.
   *
   * @param showOnlyErrors whether the rendered fragment should include only higher-severity alerts
   *     instead of the full alert list
   * @return HTML fragment containing the rendered alerts for direct inclusion in legacy page output
   */
  HTMLNode createAlerts(boolean showOnlyErrors);

  /**
   * Renders the default summary fragment used by legacy HTTP/admin views.
   *
   * <p>This overload retains the historical default summary behavior used by the existing shell,
   * usually a compact summary of higher-severity alerts. Callers that need explicit one-line or
   * multi-line behavior should use {@link #createSummary(boolean)} instead.
   *
   * @return HTML summary fragment representing the default legacy-shell alert summary view
   */
  HTMLNode createSummary();

  /**
   * Renders a summary fragment in either one-line or full-box mode.
   *
   * <p>This method supports the two summary layouts currently needed by the shared shell. Depending
   * on implementation state and alert severity, the result may be a populated summary fragment, an
   * intentionally empty marker node, or {@code null} when no summary should be shown at all.
   *
   * @param oneLine whether to render the compact single-line summary instead of the fuller box
   *     presentation
   * @return summary fragment for the requested mode, an empty marker node, or {@code null} when
   *     summary rendering is suppressed
   */
  HTMLNode createSummary(boolean oneLine);
}
