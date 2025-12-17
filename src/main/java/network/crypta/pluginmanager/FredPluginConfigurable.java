package network.crypta.pluginmanager;

import network.crypta.config.SubConfig;

/**
 * Exposes plugin configuration options to the node's configuration system and UI.
 *
 * <p>Implement this interface when a plugin needs to define persistent configuration parameters
 * that are loaded and saved by the node. The node provides the storage lifecycle (read on startup,
 * write on change) and integrates the plugin's options into the global configuration UI, including
 * a dedicated menu entry for the plugin. Plugins are expected to register their options during
 * {@link #setupConfig(SubConfig)} and to use localized text for user-facing descriptions by also
 * implementing {@link FredPluginL10n}.
 *
 * <p>The l10n key for the menu label is {@code ConfigToadlet.full.package.Classname.label}. The key
 * for the menu tooltip is {@code ConfigToadlet.full.package.Classname.tooltip}.
 *
 * <p>The parameters are stored in an unencrypted plaintext file in the node's configuration
 * directory using the filename {@code plugin-full.package.Classname.ini}.
 *
 * <ul>
 *   <li><b>Registration:</b> Define all options on the provided {@link SubConfig}.
 *   <li><b>Persistence:</b> Let the node load and save option values automatically.
 *   <li><b>Presentation:</b> Provide translated labels and descriptions via {@link FredPluginL10n}.
 * </ul>
 *
 * <p>Plugins may force a write of the configuration file by calling {@code
 * pluginRespirator.storeConfig()}, but this is only necessary if the plugin modifies a parameter
 * programmatically without a corresponding user action.
 */
public interface FredPluginConfigurable extends FredPluginL10n {
  /**
   * Registers the plugin's configuration options with the provided {@link SubConfig}.
   *
   * <p>The node calls this method during plugin initialization, before the plugin's {@code
   * runPlugin} entry point, and it does so on the calling thread (that is, not in a newly created
   * thread). Implementations should restrict themselves to declaring configuration entries (keys,
   * defaults, and localized descriptions) on {@code subconfig}. Avoid performing I/O, starting
   * background threads, or doing other heavyweight initialization here, because doing so can delay
   * plugin startup and UI availability.
   *
   * <pre>{@code
   * public void setupConfig(SubConfig subconfig) {
   *   // Register options on subconfig (keys, defaults, descriptions).
   * }
   * }</pre>
   *
   * @param subconfig configuration section for this plugin; register keys, defaults, and
   *     descriptions
   */
  void setupConfig(SubConfig subconfig);
}
