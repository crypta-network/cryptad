/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.support.plugins.helpers1;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.PageMaker;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.pluginmanager.PluginRespirator;

public class PluginContext {

	public final PluginRespirator pluginRespirator;
	public final NodeClientCore clientCore;
	public final PageMaker pageMaker;
	public final HighLevelSimpleClient hlsc;
	public final Node node;

	public PluginContext(PluginRespirator pluginRespirator2) {
		this.pluginRespirator = pluginRespirator2;
		this.clientCore = pluginRespirator.getNode().getClientCore();
		this.pageMaker = pluginRespirator.getPageMaker();
		this.hlsc = pluginRespirator.getHLSimpleClient();
		this.node = pluginRespirator.getNode();
	}
}
