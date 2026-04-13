package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * HTTP toadlet that decodes user-supplied Freenet-style keys and issues a redirect to the canonical
 * location.
 *
 * <p>This endpoint is mounted at {@code /decode/} and keeps the encoded path segment intact before
 * issuing a 301 pointing at the decoded key. It supports browser keyword searches (for example,
 * Firefox {@code keyword.URL}) and other helpers that feed Freenet-style links through the HTTP
 * gateway. The generated HTML body also embeds a manual link for agents that ignore redirects.
 *
 * <p>Instances rely on {@link ToadletContext} for request-scoped state and keep no mutable fields.
 * Deployments typically register one instance and let the dispatcher invoke it concurrently; no
 * internal synchronization is necessary because the state lives in the supplied context and page
 * maker.
 *
 * <ul>
 *   <li>Responsible for translating {@code /decode/<key>} to the {@code /<key>} target.
 *   <li>Provides a visible fallback link when redirect handling is disabled or blocked.
 *   <li>Honors full-access checks by surfacing any configured alert summaries in the response.
 * </ul>
 *
 * @see Toadlet
 * @see ToadletContext
 */
public class DecodeToadlet extends ContentToadlet {
  DecodeToadlet(HighLevelSimpleClient client) {
    super(client);
  }

  /**
   * Handles GET requests under {@code /decode/} by emitting a 301 redirect and a manual fallback
   * link.
   *
   * <p>The method preserves the request path after the toadlet mount point, prepends a leading
   * slash to form a Freenet key, and builds a small HTML page that includes both an automatic
   * redirect and a clickable anchor. When full access is permitted, any configured alert summary is
   * added to the page, so callers still see status banners while being forwarded. The method writes
   * the response immediately; callers should not attempt further output after invocation.
   *
   * @param uri fully qualified request URI supplied by the HTTP stack; never mutated by this
   *     handler
   * @param request HTTP request wrapper containing the original path segment after the decoding
   *     mount point
   * @param ctx toadlet context used for permission checks, page creation, and response streaming
   * @throws ToadletContextClosedException if the context output channel closes before the reply is
   *     written
   * @throws IOException if generating or sending the redirect page encounters an I/O failure
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {

    PageNode page = ctx.getPageMaker().getPageNode("Redirect to Decoded link", ctx);
    HTMLNode contentNode = page.getContentNode();

    if (ctx.isAllowedFullAccess()) contentNode.addChild(ctx.getAlertManager().createSummary());

    final String requestPath = request.getPath().substring(path().length());

    // Without this it'll try to look in the current directory which will be /decode and won't work.
    String keyToFetch = "/" + requestPath;

    // This is for when a browser can't handle 301s, should very rarely (never?) be seen.
    ctx.getPageMaker()
        .getInfobox("infobox-warning", "Decode Link", contentNode, "decode-not-redirected", true)
        .addChild("a", "href", keyToFetch, "Click Here to be re-directed");

    this.writeHTMLReply(ctx, 301, "Moved Permanently\nLocation: " + keyToFetch, page.generate());
  }

  /**
   * Returns the mount path used to dispatch decode requests to this toadlet.
   *
   * <p>The path is a constant {@code /decode/} with a trailing slash so that the following path
   * segments are treated as the encoded key to redirect. Dispatchers rely on this value to strip
   * the prefix before handing the remaining portion to {@link #handleMethodGET(URI, HTTPRequest,
   * ToadletContext)}; callers should avoid trimming or normalizing it further to preserve
   * compatibility with existing bookmarks and browser integrations.
   *
   * @return immutable mount path string {@code /decode/} used during HTTP registration
   */
  @Override
  public String path() {
    return "/decode/";
  }
}
