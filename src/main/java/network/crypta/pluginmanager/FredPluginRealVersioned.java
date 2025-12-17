package network.crypta.pluginmanager;

/**
 * Comparable plugin version identifier.
 *
 * <p>This interface exposes a plugin's version as a single monotonically ordered numeric value so
 * the node and plugin manager can compare two versions efficiently without parsing human-readable
 * strings. The primary expectation is that larger values represent newer releases, enabling simple
 * ordering (for example: {@code 150} compares as newer than {@code 20}).
 *
 * <p>Implementations should treat the returned value as stable metadata for the plugin build. The
 * node may use it for display, compatibility decisions, update selection, or logging. Because it is
 * a plain {@code long}, the value supports fast comparisons and avoids locale- or format-sensitive
 * parsing rules.
 *
 * <p><b>Notable behaviors</b>
 *
 * <ul>
 *   <li>Comparison is numeric only; no semantic-version components are implied.
 *   <li>The version is intended to be totally ordered within a plugin's release history.
 * </ul>
 */
public interface FredPluginRealVersioned {

  /**
   * Returns the plugin's comparable version value.
   *
   * <p>The returned {@code long} is used for ordering plugin releases. Implementations should
   * ensure that the value increases as the plugin evolves, so consumers can reliably treat larger
   * numbers as newer versions. This method is expected to be cheap and side-effect free, and it may
   * be called multiple times during plugin loading and update checks.
   *
   * @return a numeric version identifier where larger values sort as newer plugin releases.
   */
  long getRealVersion();

  // There is no point in reporting the dependencies or the minimum node version here,
  // because the plugin has already been loaded.

  // SCM-specific revisions are not exposed here: Git uses hashes, which are strings.

}
