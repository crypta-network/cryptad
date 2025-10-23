package network.crypta.l10n;

import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.pluginmanager.FredPluginBaseL10n;

/**
 * Localization bridge for plugins.
 *
 * <p>This class is a thin wrapper that configures a {@link BaseL10n} instance from information
 * provided by a plugin via {@link network.crypta.pluginmanager.FredPluginBaseL10n}. It enables the
 * node to look up translated strings for a plugin without knowing where the plugin stores its l10n
 * resources or which class loader should be used to find them.
 *
 * <p>Why not a static utility? Each plugin may use different resource base paths, filename masks,
 * override locations, and class loaders. A per-plugin instance keeps these concerns isolated and
 * avoids coupling between plugins.
 *
 * <h2>Threading</h2>
 *
 * <p>{@code PluginL10n} itself is immutable after construction. Thread-safety of lookups and state
 * changes (for example, language selection or overrides) is governed by the underlying {@link
 * BaseL10n}; see its documentation for details.
 *
 * @author Artefact2
 */
public class PluginL10n {

  private final BaseL10n b;

  /**
   * Create a new instance using the node's currently selected language.
   *
   * <p>The selected language is obtained from {@link NodeL10n#getBase()} and used to initialize the
   * internal {@link BaseL10n}. Resource resolution uses the plugin's class loader and the base path
   * and filename masks provided by the plugin.
   *
   * @param plugin plugin that supplies resource paths, filename masks (containing {@code ${lang}}),
   *     an override-file mask (containing {@code ${lang}}), and the class loader to use; must not
   *     be {@code null}
   * @throws NullPointerException if {@code plugin} is {@code null}
   */
  public PluginL10n(FredPluginBaseL10n plugin) {
    this(plugin, NodeL10n.getBase().getSelectedLanguage());
  }

  /**
   * Create a new instance with an explicit language.
   *
   * <p>Call this once during plugin initialization and cache the resulting object to reuse its
   * {@link BaseL10n}. The plugin provides the resource base path, masks (where {@code ${lang}} is
   * replaced by {@link BaseL10n.LANGUAGE#shortCode}), an override-file mask, and a class loader for
   * resource lookup.
   *
   * @param plugin plugin that supplies resource configuration and class loader; must not be {@code
   *     null}
   * @param lang language to use for the initial selection; must not be {@code null}
   * @throws NullPointerException if {@code plugin} is {@code null}
   * @throws java.util.MissingResourceException if {@code lang} is {@code null} (thrown by {@link
   *     BaseL10n#setLanguage(BaseL10n.LANGUAGE)})
   */
  public PluginL10n(FredPluginBaseL10n plugin, final LANGUAGE lang) {
    this.b =
        new BaseL10n(
            plugin.getL10nFilesBasePath(),
            plugin.getL10nFilesMask(),
            plugin.getL10nOverrideFilesMask(),
            lang,
            plugin.getPluginClassLoader());
  }

  /**
   * Return the {@link BaseL10n} configured for this plugin.
   *
   * <p>The returned instance is the same object for the lifetime of this {@code PluginL10n} and may
   * be cached by callers.
   *
   * @return the non-{@code null} localization helper
   */
  public BaseL10n getBase() {
    return this.b;
  }
}
