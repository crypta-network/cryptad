package network.crypta.pluginmanager;

import network.crypta.l10n.BaseL10n.LANGUAGE;

/**
 * Supplies localized strings for a plugin when it integrates with the node's UI.
 *
 * <p>Implement this interface when the node needs to ask a plugin to translate user-facing text,
 * such as navigation labels, tooltips, and configuration option descriptions. The node passes a
 * plugin-provided instance to UI components (for example, when adding links via {@link
 * network.crypta.clients.http.PageMaker#addNavigationLink(String, String, String, String, boolean,
 * network.crypta.clients.http.LinkEnabledCallback, FredPluginL10n)}), and then calls {@link
 * #getString(String)} whenever it must render a localized string.
 *
 * <p>Implementations typically wrap a small resource bundle or map keyed by stable string IDs.
 * Callers may invoke these methods frequently and from different threads while building pages or
 * reacting to configuration changes; implementations should therefore be inexpensive and either
 * thread-safe or clearly documented as requiring external synchronization. Language changes are
 * delivered via {@link #setLanguage(LANGUAGE)} and should update subsequent lookups.
 *
 * <ul>
 *   <li><b>Lookup:</b> Map stable keys to localized, human-readable strings.
 *   <li><b>Language switching:</b> Apply node-selected languages for the current session.
 *   <li><b>UI integration:</b> Support navigation and configuration pages without duplicating node
 *       localization logic.
 * </ul>
 *
 * @author saces
 * @see network.crypta.clients.http.PageMaker
 * @see FredPluginConfigurable
 * @see FredPluginBaseL10n
 */
public interface FredPluginL10n {

  /**
   * Returns a localized string for the given key using the plugin's current language.
   *
   * <p>The node calls this method to obtain translated, user-visible text owned by the plugin. The
   * {@code key} is a stable identifier (not the localized text itself) that the plugin defines and
   * documents for its own UI surfaces. Implementations should return a value suitable for display
   * as plain text within HTML pages and should avoid expensive computation because the node may
   * request many strings during page rendering.
   *
   * <p>If a key is unknown, implementations may return a fallback string (for example, the key
   * itself or a default language value); callers should not assume that missing keys throw.
   *
   * @param key stable string identifier used to select a localized value; must be non-null and
   *     should be a plugin-defined constant
   * @return localized string corresponding to {@code key} in the currently active language
   */
  String getString(String key);

  /**
   * Updates the plugin's currently active language for subsequent string lookups.
   *
   * <p>The node calls this method when the user changes the UI language or when the node decides to
   * adjust language selection for the current session. Implementations should update the internal
   * localization state (for example, by swapping bundles or invalidating caches) so that future
   * {@link #getString(String)} calls return values for {@code newLanguage}. Calling this method
   * repeatedly with the same value should be treated as a no-op where practical.
   *
   * @param newLanguage language to activate for this plugin; must be non-null and supported
   */
  void setLanguage(LANGUAGE newLanguage);
}
