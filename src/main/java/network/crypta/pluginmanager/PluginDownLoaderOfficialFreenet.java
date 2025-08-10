package network.crypta.pluginmanager;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginDescription;

public class PluginDownLoaderOfficialFreenet extends PluginDownLoaderFreenet {

	public PluginDownLoaderOfficialFreenet(HighLevelSimpleClient client, Node node, boolean desperate) {
		super(client, node, desperate);
	}

	@Override
	public FreenetURI checkSource(String source) throws PluginNotFoundException {
		OfficialPluginDescription desc = node.getPluginManager().getOfficialPlugin(source);
		if(desc == null) throw new PluginNotFoundException("Not in the official plugins list: "+source);
		if(desc.uri != null)
			return desc.uri;
		else {
			return node.getNodeUpdater().getURI().setDocName(source).setSuggestedEdition(desc.recommendedVersion).sskForUSK();
		}
	}
	
	@Override
	String getPluginName(String source) throws PluginNotFoundException {
		return source + ".jar";
	}
	
	public boolean isOfficialPluginLoader() {
		return true;
	}

	public PluginDownLoader<FreenetURI> getRetryDownloader() {
		return new PluginDownLoaderOfficialFreenet(hlsc, node, true);
	}

}
