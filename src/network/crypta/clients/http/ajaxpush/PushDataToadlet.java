package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.BaseUpdateableElement;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.Base64;
import network.crypta.support.Logger;
import network.crypta.support.api.HTTPRequest;

/** A toadlet that provides the current data of pushed elements. It requires the requestId and the elementId parameters. */
public class PushDataToadlet extends Toadlet {

	private static volatile boolean	logMINOR;

	static {
		Logger.registerClass(PushDataToadlet.class);
	}

	public PushDataToadlet(HighLevelSimpleClient client) {
		super(client);
	}

	public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
		String requestId = req.getParam("requestId");
		String elementId = req.getParam("elementId");
		elementId = elementId.replace(" ", "+");// This is needed, because BASE64 has '+', but it is a HTML escape for ' '
		if (logMINOR) {
			Logger.minor(this, "Getting data for element:" + elementId);
		}
		BaseUpdateableElement node = ((SimpleToadletServer) ctx.getContainer()).getPushDataManager().getRenderedElement(requestId, elementId);
		if (logMINOR) {
			Logger.minor(this, "Data got element:" + node.generateChildren());
		}
		writeHTMLReply(ctx, 200, "OK", UpdaterConstants.SUCCESS + ":" + Base64.encodeStandard(node.getUpdaterType().getBytes(StandardCharsets.UTF_8)) + ":" + Base64.encodeStandard(node.generateChildren().getBytes(StandardCharsets.UTF_8)));
	}

	@Override
	public String path() {
		return UpdaterConstants.dataPath;
	}

}
