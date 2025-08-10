package network.crypta.pluginmanager;

import network.crypta.l10n.BaseL10n.LANGUAGE;

/**
 * Interface that has to be implemented for plugins that wants to use
 * the node's localization system (recommended).
 *
 * Those methods are called by the node when plugin l10n data are needed,
 * ex. to automate things in the translation page.
 *
 * @author Artefact2
 */
public interface FredPluginBaseL10n {

	/**
	 * Called when the plugin should change its language.
	 * @param newLanguage New language to use.
	 */
    void setLanguage(LANGUAGE newLanguage);

	String getL10nFilesBasePath();

	String getL10nFilesMask();

	String getL10nOverrideFilesMask();

	ClassLoader getPluginClassLoader();
}
