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

/** A toadlet that the client can use for push failover. It requires the requestId and originalRequestId parameter. */
public class PushFailoverToadlet extends Toadlet {

	private static volatile boolean	logMINOR;

	static {
		Logger.registerClass(PushFailoverToadlet.class);
	}

	public PushFailoverToadlet(HighLevelSimpleClient client) {
		super(client);
	}

	public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
		String requestId = req.getParam("requestId");
		String originalRequestId = req.getParam("originalRequestId");
		boolean result = ((SimpleToadletServer) ctx.getContainer()).getPushDataManager().failover(originalRequestId, requestId);
		if (logMINOR) {
			Logger.minor(this, "Failover from:" + originalRequestId + " to:" + requestId + " with result:" + result);
		}
		writeHTMLReply(ctx, 200, "OK", result ? UpdaterConstants.SUCCESS : UpdaterConstants.FAILURE);
	}

	@Override
	public String path() {
		return UpdaterConstants.failoverPath;
	}

}
