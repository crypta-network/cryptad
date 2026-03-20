package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * Offline help toadlet that serves localized guidance for the Crypta web interface. It builds a
 * lightweight help page from bundled resources so operators have access to terminology,
 * connectivity tips, and documentation even when external Freesites or upstream networks are
 * unreachable.
 *
 * <p>The toadlet assembles a set of infoboxes describing Crypta concepts, keys, and basic network
 * setup using {@link NodeL10n} strings, ensuring translations follow the user's selected locale. It
 * relies on the surrounding {@link ToadletContext} to source the page maker, alert summaries, and
 * access checks; when full access is granted it surfaces pending alerts before the help content.
 * Output is rendered as standard HTML and returned as a 200 OK response suitable for embedding into
 * the FProxy navigation flow.
 *
 * <p>Instances are effectively stateless apart from the inherited client binding, so they can be
 * shared across requests without additional synchronization. Callers register the toadlet at the
 * {@link #path()} URI to expose the documentation to users.
 *
 * <ul>
 *   <li>Responsibilities: render localized help, outline key types, and summarize connectivity
 *       steps.
 *   <li>Notable behaviors: includes alert summaries only when full access is permitted.
 *   <li>Thread-safety: read-only across requests; relies on external context for mutable state.
 * </ul>
 *
 * @author Juiceman
 * @see Toadlet
 * @see ToadletContext
 * @see NodeL10n
 */
public class SimpleHelpToadlet extends Toadlet {
  private static final String INFOBOX_CONTENT = "infobox-content";

  SimpleHelpToadlet(HighLevelSimpleClient client) {
    super(client);
  }

  /**
   * Handles HTTP GET requests by rendering the offline help page and streaming it to the client.
   * The method builds a page composed of descriptive and connectivity-focused infoboxes, injects
   * alert summaries when the requester has full access, and finalizes the response with a 200 OK
   * status. It performs no modification of the server state, making repeated calls idempotent and
   * safe for refresh or bookmark access patterns.
   *
   * <p>All content is derived from localization bundles so that translations remain consistent with
   * the node's configured language. The returned HTML explains core key types (CHK, SSK, USK) and
   * offers short guidance on tasks such as port forwarding to improve reachability. Should the
   * toadlet context close mid-write or an I/O fault occurs, the method surfaces the corresponding
   * exception to the caller for upstream handling.
   *
   * <pre>{@code
   * // Example: serving the help toadlet within an HTTP handler
   * helpToadlet.handleMethodGET(requestUri, httpRequest, toadletContext);
   * }</pre>
   *
   * @param uri requested help page URI; provided for signature parity and logging context.
   * @param request inbound HTTP request containing headers and parameters; never modified here.
   * @param ctx active toadlet context that supplies page construction utilities and access checks.
   * @throws ToadletContextClosedException if the context is closed before, the response is flushed.
   * @throws IOException if writing the generated HTML to the client output stream fails.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {

    PageNode page =
        ctx.getPageMaker()
            .getPageNode("Crypta " + NodeL10n.getBase().getString("FProxyToadlet.help"), ctx);
    HTMLNode contentNode = page.getContentNode();

    if (ctx.isAllowedFullAccess()) contentNode.addChild(ctx.getAlertManager().createSummary());

    // Description infobox
    HTMLNode helpScreenContent1 =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_CONTENT,
                NodeL10n.getBase().getString("SimpleHelpToadlet.descriptionTitle"),
                contentNode,
                "freenet-description",
                true);
    helpScreenContent1.addChild(
        "#", NodeL10n.getBase().getString("SimpleHelpToadlet.descriptionText"));

    // Definitions infobox
    HTMLNode helpScreenContent2 =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_CONTENT,
                NodeL10n.getBase().getString("SimpleHelpToadlet.definitionsTitle"),
                contentNode,
                "freenet-definitions",
                true);

    HTMLNode table =
        helpScreenContent2.addChild(
            "table", new String[] {"border", "style"}, new String[] {"0", "border: none"});

    HTMLNode row = table.addChild("tr");
    row.addChild("td", "style", "border: none");

    row.addChild("#", NodeL10n.getBase().getString("SimpleHelpToadlet.CHK"));
    row.addChild("br");
    row.addChild("#", NodeL10n.getBase().getString("SimpleHelpToadlet.SSK"));
    row.addChild("br");
    row.addChild("#", NodeL10n.getBase().getString("SimpleHelpToadlet.USK"));

    // Port forwarding, etc.
    HTMLNode helpScreenContent3 =
        ctx.getPageMaker()
            .getInfobox(
                INFOBOX_CONTENT,
                NodeL10n.getBase().getString("SimpleHelpToadlet.connectivityTitle"),
                contentNode,
                "freenet-connectivity",
                true);
    helpScreenContent3.addChild(
        "#", NodeL10n.getBase().getString("SimpleHelpToadlet.connectivityText"));

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  /**
   * Returns the absolute toadlet path where this help page is registered within the HTTP server.
   * The trailing slash aligns with other navigation entries in the FProxy UI and allows relative
   * resource resolution for localized assets included in the rendered page. Callers typically use
   * this value during router registration to bind the help content to a stable, discoverable
   * endpoint.
   *
   * @return the canonical help path {@code "/help/"} used when exposing the toadlet to clients.
   */
  @Override
  public String path() {
    return "/help/";
  }
}
