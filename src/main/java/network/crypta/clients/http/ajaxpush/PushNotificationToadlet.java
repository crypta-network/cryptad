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
import network.crypta.clients.http.updateableelements.PushDataManager;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.Base64;
import network.crypta.support.Logger;
import network.crypta.support.api.HTTPRequest;

/** This toadlet provides notifications for clients. It will block until one is present. It requires the requestId parameter. */
public class PushNotificationToadlet extends Toadlet {

	private static volatile boolean	logMINOR;

	static {
		Logger.registerClass(PushNotificationToadlet.class);
	}

	public PushNotificationToadlet(HighLevelSimpleClient client) {
		super(client);
	}

	public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
		String requestId = req.getParam("requestId");
		PushDataManager.UpdateEvent event = ((SimpleToadletServer) ctx.getContainer()).getPushDataManager().getNextNotification(requestId);
		if (event != null) {
			String elementRequestId = event.getRequestId();
			String elementId = event.getElementId();
			writeHTMLReply(ctx, 200, "OK", UpdaterConstants.SUCCESS + ":" + Base64.encodeStandard(elementRequestId.getBytes(StandardCharsets.UTF_8)) + UpdaterConstants.SEPARATOR + elementId);
			if (logMINOR) {
				Logger.minor(this, "Notification got:" + event);
			}
		} else {
			writeHTMLReply(ctx, 200, "OK", UpdaterConstants.FAILURE);
		}
	}

	@Override
	public String path() {
		return UpdaterConstants.notificationPath;
	}

}
