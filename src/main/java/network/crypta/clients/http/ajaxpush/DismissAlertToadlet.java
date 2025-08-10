package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.HTMLDecoder;
import network.crypta.support.Logger;
import network.crypta.support.api.HTTPRequest;

/** This toadlet is used to dismiss alerts from the client side */
public class DismissAlertToadlet extends Toadlet {

	private static volatile boolean	logMINOR;

	static {
		Logger.registerClass(DismissAlertToadlet.class);
	}

	public DismissAlertToadlet(HighLevelSimpleClient client) {
		super(client);
	}

	public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
		// The anchor is used to identify the alert
		String anchor = HTMLDecoder.decode(req.getParam("anchor"));
		if (logMINOR) {
			Logger.minor(this, "Dismissing alert with anchor:" + anchor);
		}
		// Dismiss the alert
		//boolean success = ((SimpleToadletServer) ctx.getContainer()).getCore().alerts.dismissByAnchor(anchor);
		//TODO:it's disabled
		boolean success = true;
		writeHTMLReply(ctx, 200, "OK", success ? UpdaterConstants.SUCCESS : UpdaterConstants.FAILURE);
	}

	@Override
	public String path() {
		return UpdaterConstants.dismissAlertPath;
	}

}
