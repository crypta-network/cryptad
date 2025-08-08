package network.crypta.clients.http;

import java.io.File;
import java.util.Hashtable;
import java.util.Set;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;

public class LocalFileN2NMToadlet extends LocalFileBrowserToadlet {

	public static final String PATH = "/n2nm-browse/";
	public static final String POST_TO = "/send_n2ntm/";

	public LocalFileN2NMToadlet (NodeClientCore core, HighLevelSimpleClient highLevelSimpleClient) {
		super(core, highLevelSimpleClient);
	}

	@Override
	public String path() {
		return PATH;
	}

	@Override
	protected String postTo() {
		return POST_TO;
	}

	@Override
	protected String startingDir() {
		return defaultUploadDir();
	}

	@Override
	protected boolean allowedDir(File path) {
		return core.allowUploadFrom(path);
	}

	@Override
	protected void createSelectDirectoryButton(HTMLNode fileRow, String path, HTMLNode persistence) {
	}

    @Override
	protected Hashtable<String, String> persistenceFields (Hashtable<String, String> set) {
		Hashtable<String, String> fieldPairs = new Hashtable<String, String>();
		String message = set.get("message");
		if (message != null) fieldPairs.put("message", message);
		Set<String> keys = set.keySet();
		for (String key : keys) {
			if (key.startsWith("node_")) {
				fieldPairs.put(key, "1");
			}
		}
		return fieldPairs;
	}
}
