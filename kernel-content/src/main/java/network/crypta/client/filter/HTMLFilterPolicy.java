package network.crypta.client.filter;

/**
 * Stores the process-wide HTML filtering policy values that must remain visible across module
 * boundaries.
 *
 * <p>The legacy admin UI still needs to read and update a few HTML filtering knobs even though the
 * full filtering engine now lives in a different module. This class provides the smallest shared
 * state necessary for that arrangement: whether the bundled M3U helper is injected and the minimum
 * delays enforced for same-page and redirecting {@code meta refresh} tags. Keeping those values in
 * a detached holder lets lightweight callers participate in configuration without depending on the
 * runtime-owned filter implementation.
 *
 * <p>The state is intentionally static and global because the underlying behavior has always been
 * process-wide. Updates therefore affect later filter operations across the JVM, not only the
 * caller that changed the value. The class performs no validation or synchronization on its own; it
 * relies on higher-level configuration code to supply already-validated values and to coordinate
 * when changes become visible to operators.
 *
 * <ul>
 *   <li>The defaults match the historical HTML filter defaults.
 *   <li>Negative refresh intervals mean the corresponding tag should be rejected outright.
 *   <li>The stored values are compatibility settings, not a full per-request policy model.
 * </ul>
 */
public final class HTMLFilterPolicy {
  /** if true, embed m3u player. Enabled when fproxy javascript is enabled. */
  private static boolean embedM3uPlayer = true;

  /** -1 means don't allow it */
  private static int metaRefreshSamePageMinInterval = 1;

  /** -1 means don't allow it */
  private static int metaRefreshRedirectMinInterval = 30;

  private HTMLFilterPolicy() {}

  /**
   * Reports whether the bundled M3U player should be embedded for allowed media content.
   *
   * <p>When this flag is enabled, later HTML filtering passes may inline the lightweight helper
   * needed to play eligible M3U-based media content directly in the browser. Disabling the flag
   * leaves the rest of the filtering pipeline intact but prevents that convenience layer from being
   * added to sanitized output.
   *
   * @return {@code true} when the player snippet is currently enabled for future filtering work
   */
  public static boolean isEmbedM3uPlayerEnabled() {
    return embedM3uPlayer;
  }

  /**
   * Enables or disables automatic embedding of the bundled M3U player script.
   *
   * <p>This value is global rather than request-scoped. Callers should update it only from
   * configuration or bootstrap code that intends to change the node-wide HTML filtering behavior
   * for later requests.
   *
   * @param enabled {@code true} to inject the helper script whenever eligible media tags are
   *     preserved during later filtering passes
   */
  public static void setEmbedM3uPlayerEnabled(boolean enabled) {
    embedM3uPlayer = enabled;
  }

  /**
   * Returns the minimum number of seconds required between meta-refresh events that reload the same
   * page.
   *
   * <p>This threshold controls refresh tags that keep the browser in the current location. Small
   * values allow gently updating status pages, while negative values reject the behavior entirely.
   * The number is interpreted in seconds because that is how HTML {@code meta refresh} delays are
   * expressed in content.
   *
   * @return minimum same-page refresh delay in seconds, or {@code -1} when such refreshes should
   *     always be dropped
   */
  public static int getMetaRefreshSamePageMinInterval() {
    return metaRefreshSamePageMinInterval;
  }

  /**
   * Updates the interval guarding same-page meta-refresh operations.
   *
   * <p>The value is stored exactly as supplied, so the policyholder stays detached from UI and
   * validation rules. Callers are responsible for enforcing any range checks before writing the new
   * setting.
   *
   * @param interval number of seconds enforced between refreshes targeting the current URI, or a
   *     negative value to disable the behavior entirely
   */
  public static void setMetaRefreshSamePageMinInterval(int interval) {
    metaRefreshSamePageMinInterval = interval;
  }

  /**
   * Returns the minimum number of seconds required before a redirecting meta-refresh may survive
   * filtering.
   *
   * <p>This setting applies to refresh tags that move the browser to a new URL. Redirecting
   * refreshes are usually more sensitive than same-page reloads because they can be used to rush
   * navigation or hide the final destination, so the default delay is higher.
   *
   * @return minimum redirect delay in seconds, or {@code -1} when redirecting refreshes are
   *     forbidden outright
   */
  public static int getMetaRefreshRedirectMinInterval() {
    return metaRefreshRedirectMinInterval;
  }

  /**
   * Sets the minimum delay enforced for meta-refreshes that redirect the browser to a new URL.
   *
   * <p>Like the other policy values in this class, the assignment is immediate and process-wide for
   * future filtering work. The method does not reject unusual values because validation belongs in
   * the configuration layer that owns the operator-facing setting.
   *
   * @param interval number of seconds required before allowing a redirecting refresh to pass, or a
   *     negative value to reject redirect refreshes completely
   */
  public static void setMetaRefreshRedirectMinInterval(int interval) {
    metaRefreshRedirectMinInterval = interval;
  }
}
