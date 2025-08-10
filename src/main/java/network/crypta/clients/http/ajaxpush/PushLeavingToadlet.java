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

/**
 * This toadlet allows the client to notify the server about page leaving. All of it's data is then erased, it's elements disposed, and notifications removed. It needs the
 * requestId parameter.
 */
public class PushLeavingToadlet extends Toadlet {

	private static volatile boolean	logMINOR;

	static {
		Logger.registerClass(PushLeavingToadlet.class);
	}

	public PushLeavingToadlet(HighLevelSimpleClient client) {
		super(client);
	}

	public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
		String requestId = req.getParam("requestId");
		boolean deleted = ((SimpleToadletServer) ctx.getContainer()).getPushDataManager().leaving(requestId);
		if (logMINOR) {
			Logger.minor(this, "Page leaving. requestid:" + requestId + " deleted:" + deleted);
		}
		writeHTMLReply(ctx, 200, "OK", UpdaterConstants.SUCCESS);
	}

	@Override
	public String path() {
		return UpdaterConstants.leavingPath;
	}

}
