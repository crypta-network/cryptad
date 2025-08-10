package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.Logger;
import network.crypta.support.api.HTTPRequest;

/** This toadlet receives keepalives. It requires the requestId parameter. If the keepalive is failed, the request is already deleted. */
public class PushKeepaliveToadlet extends Toadlet {

	private static volatile boolean	logMINOR;

	static {
		Logger.registerClass(PushKeepaliveToadlet.class);
	}

	public PushKeepaliveToadlet(HighLevelSimpleClient client) {
		super(client);
	}

	public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
		String requestId = req.getParam("requestId");
		if (logMINOR) {
			Logger.minor(this, "Got keepalive:" + requestId);
		}
		boolean success = ((SimpleToadletServer) ctx.getContainer()).getPushDataManager().keepAliveReceived(requestId);
		if (success) {
			writeHTMLReply(ctx, 200, "OK", UpdaterConstants.SUCCESS);
		} else {
			writeHTMLReply(ctx, 200, "OK", UpdaterConstants.FAILURE);
		}
	}

	@Override
	public String path() {
		return UpdaterConstants.keepalivePath;
	}

}
