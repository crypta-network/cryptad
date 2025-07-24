package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.clients.http.PageNode;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.TesterElement;
import network.crypta.support.api.HTTPRequest;

/** This toadlet provides a simple page with pushed elements, making it suitable for automated tests. */
public class PushTesterToadlet extends Toadlet {

	public PushTesterToadlet(HighLevelSimpleClient client) {
		super(client);
	}

	public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
		PageNode pageNode = ctx.getPageMaker().getPageNode("Push tester", ctx, new RenderParameters().renderNavigationLinks(false));
		for (int i = 0; i < 600; i++) {
			pageNode.getContentNode().addChild(new TesterElement(ctx, String.valueOf(i), 100));
		}
		writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	@Override
	public String path() {
		return "/pushtester/";
	}

}
