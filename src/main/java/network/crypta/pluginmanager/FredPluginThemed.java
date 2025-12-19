package network.crypta.pluginmanager;

import network.crypta.clients.http.PageMaker.THEME;

/**
 * Theme integration for plugins that do not use {@code PageMaker}.
 *
 * <p>This interface allows a plugin to receive the node's current HTML/CSS theme selection without
 * depending on the higher-level {@code PageMaker} helpers. It exists primarily for legacy or
 * low-level plugin UIs that still render HTML but want to stay visually consistent with the node's
 * own pages.
 *
 * <p>In typical usage the plugin is loaded, the node determines the active theme, and then invokes
 * {@link #setTheme(THEME)} to provide the current value. Implementations usually store the provided
 * theme and use it when rendering subsequent pages. If the theme can change during runtime, this
 * method may be called again; implementations should treat the call as an update and should avoid
 * expensive work on the caller thread.
 *
 * <p><b>Guidance</b>
 *
 * <ul>
 *   <li>Prefer using {@code PageMaker} for new code when possible.
 *   <li>Keep theme usage read-only: the plugin should not attempt to modify node-wide theme
 *       settings.
 * </ul>
 *
 * @see network.crypta.clients.http.PageMaker
 * @see THEME
 * @author saces
 */
public interface FredPluginThemed {

  /**
   * Supplies the current node theme to the plugin.
   *
   * <p>The node calls this method to inform the plugin of the theme that should be used for HTML
   * rendering so plugin pages match the node UI. Implementations generally persist the value and
   * consult it when generating responses. Calls may repeat over time; treat them as updates and
   * keep the method quick and side-effect free beyond updating internal state.
   *
   * <pre>{@code
   * // Example: store the provided theme for later rendering.
   * plugin.setTheme(theme);
   * }</pre>
   *
   * @param theme the selected node theme to apply for subsequent HTML rendering, never {@code
   *     null}.
   */
  void setTheme(THEME theme);
}
