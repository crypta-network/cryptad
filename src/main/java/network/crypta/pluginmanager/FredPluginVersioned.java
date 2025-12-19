package network.crypta.pluginmanager;

/**
 * Exposes a human-readable plugin version string.
 *
 * <p>This optional capability interface allows a plugin to report a version intended for display to
 * users (for example in UI, logs, or diagnostics). The value is treated as a free-form string such
 * as {@code "1.0.3"} and is not required to be machine-sortable or semantically comparable.
 * Consumers should therefore avoid parsing or ordering the value unless they fully control the
 * plugin versioning scheme.
 *
 * <p>If a plugin needs to participate in update logic or compatibility checks that require numeric
 * ordering, implement {@code FredPluginRealVersioned} instead (or in addition). That interface
 * provides an integer "real version" suitable for comparisons, while this interface remains focused
 * on user-facing presentation.
 *
 * <ul>
 *   <li><b>Primary use:</b> show a friendly version identifier to humans.
 *   <li><b>Stability:</b> the string format is plugin-defined and may change over time.
 * </ul>
 */
public interface FredPluginVersioned {
  /**
   * Returns the plugin's user-facing version identifier.
   *
   * <p>The returned value is intended for display rather than comparison. Implementations may use
   * semantic versioning, date-based versions, or any other string that makes sense for their
   * release process. Callers should treat the returned string as opaque and should not assume it is
   * numeric, ordered, or parseable.
   *
   * @return a human-readable version string for display; typically non-null and non-empty
   */
  String getVersion();
}
