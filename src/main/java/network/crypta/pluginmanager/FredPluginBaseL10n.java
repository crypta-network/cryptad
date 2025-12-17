package network.crypta.pluginmanager;

import network.crypta.l10n.BaseL10n.LANGUAGE;

/**
 * Integrates a plugin with the node's localization (l10n) infrastructure.
 *
 * <p>This interface provides the minimal hooks the node needs to discover and consume translation
 * resources shipped by a plugin. The node uses these methods when it needs metadata about a
 * plugin's translation files (for example, to enumerate available languages and to support the
 * translation UI), and when it needs to notify the plugin that the active language changed.
 *
 * <p>Implementations typically treat the return values as stable configuration for the plugin and
 * keep them inexpensive to compute. The node may call these methods multiple times and may do so
 * from different threads; implementations should therefore be either thread-safe or explicitly
 * document their synchronization expectations.
 *
 * <ul>
 *   <li><b>Resource discovery:</b> Provide a base path and filename masks used to locate l10n data.
 *   <li><b>Override support:</b> Provide an optional mask for user-supplied override files.
 *   <li><b>Loading context:</b> Provide the {@link ClassLoader} used to load plugin resources.
 * </ul>
 *
 * @author Artefact2
 */
public interface FredPluginBaseL10n {

  /**
   * Updates the plugin's currently active language.
   *
   * <p>The node calls this method when the user selects a new UI language or when the node decides
   * that the active language should change for the current session. Implementations are expected to
   * update any internal state that influences localization, such as cached bundles or resolved
   * message tables, so that subsequent lookups use the new language. Calling this method multiple
   * times with the same value should be treated as a no-op where practical.
   *
   * @param newLanguage the new language to activate; must be non-null and supported by the plugin
   */
  void setLanguage(LANGUAGE newLanguage);

  /**
   * Returns the base path used to locate the plugin's localization resources.
   *
   * <p>The returned value is used as a path prefix when the node searches for translation files
   * provided by the plugin. Implementations usually return a stable, relative path within the
   * plugin's packaged resources. The exact interpretation (for example, whether it is treated as a
   * directory name or a classpath prefix) is determined by the node's localization loader.
   *
   * @return a non-empty base path for l10n resources, suitable for repeated resource lookups
   */
  String getL10nFilesBasePath();

  /**
   * Returns the filename mask used to identify the plugin's bundled localization files.
   *
   * <p>The node uses this mask together with {@link #getL10nFilesBasePath()} to enumerate and load
   * the plugin's built-in translations. Implementations should return a mask that matches all
   * language variants shipped with the plugin and does not match unrelated resources.
   *
   * @return a filename mask describing the plugin's built-in l10n files, interpreted by the node
   */
  String getL10nFilesMask();

  /**
   * Returns the filename mask used to identify user-supplied override localization files.
   *
   * <p>Override files allow translations to be supplied outside the plugin's bundled resources. If
   * the plugin does not support overrides, implementations should return a mask that causes no
   * matches rather than returning {@code null}. The node uses this mask to discover candidate
   * override files and to present them in the translation workflow.
   *
   * @return a filename mask for override l10n files; return a non-matching mask to disable support
   */
  String getL10nOverrideFilesMask();

  /**
   * Returns the class loader that should be used to load the plugin's localization resources.
   *
   * <p>The node uses this class loader when it reads translation files from the plugin's packaged
   * resources. Implementations should typically return the plugin's own {@link ClassLoader}, so
   * resource lookups resolve relative to the plugin rather than the node's core classpath.
   *
   * @return the {@link ClassLoader} for loading this plugin's l10n resources, never {@code null}
   */
  ClassLoader getPluginClassLoader();
}
