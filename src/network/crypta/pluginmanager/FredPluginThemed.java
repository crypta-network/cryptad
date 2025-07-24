/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.pluginmanager;

import network.crypta.clients.http.PageMaker.THEME;

/**
 * Interface that has to be implemented for plugins that wants to use
 * nodes html look (css theme) but not PageMaker.<br /> 
 * 
 * Very geek'ish and not recommended. Use PageMaker instead. {see FredPluginL10n}
 *  
 * @author saces
 *
 */
public interface FredPluginThemed {

	void setTheme(THEME theme);

}
