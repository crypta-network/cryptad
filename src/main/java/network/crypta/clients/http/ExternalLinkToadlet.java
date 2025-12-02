package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;

/**
 * Serves a confirmation page before allowing the browser to follow external HTTP/HTTPS links.
 *
 * <p>The toadlet is invoked when a user action would open a non-FProxy URL. It renders a warning
 * page that summarizes the destination and asks the user to continue or cancel. The class keeps no
 * mutable state beyond a reference to the running {@link Node}, so it can be reused safely across
 * requests as long as the surrounding toadlet container manages threading correctly.
 *
 * <p>Typical flow:
 *
 * <ul>
 *   <li>{@link #escape(String)} builds the confirmation URL that embeds the target as a query
 *       parameter.
 *   <li>{@link #handleMethodGET(URI, HTTPRequest, ToadletContext)} renders the warning and form
 *       when the user first follows the link.
 *   <li>{@link #handleMethodPOST(URI, HTTPRequest, ToadletContext)} processes the user's choice and
 *       redirects accordingly.
 * </ul>
 *
 * <p>The handler does not attempt to validate or fetch the destination; it only mediates intent and
 * relies on upstream components for network access and policy. Because it operates on user-supplied
 * URLs, callers should ensure the surrounding flow already escaped or encoded values appropriately.
 */
public class ExternalLinkToadlet extends Toadlet {

  private static final int MAX_URL_LENGTH = 1024 * 1024;
  private static final String PATH_SEPARATOR = "/";
  private static final String EXTERNAL_LINK_SEGMENT = "external-link";

  /**
   * Public path segment served by this toadlet (e.g. {@code /external-link/}). Clients compose
   * links by appending query parameters produced by {@link #escape(String)}.
   */
  public static final String EXTERNAL_LINK_PATH =
      PATH_SEPARATOR + EXTERNAL_LINK_SEGMENT + PATH_SEPARATOR;

  /**
   * Query parameter name carrying the original external URL. The value is treated as opaque text
   * and echoed back into the confirmation form without additional validation.
   */
  public static final String MAGIC_HTTP_ESCAPE_STRING = "_CHECKED_HTTP_";

  private static final String TAG_INPUT = "input";
  private static final String ATTR_VALUE = "value";

  private final Node node;

  ExternalLinkToadlet(HighLevelSimpleClient client, Node node) {
    super(client);
    this.node = node;
  }

  @Override
  public String path() {
    return EXTERNAL_LINK_PATH;
  }

  /**
   * Handles form submissions from the confirmation page and issues an HTTP redirect to the chosen
   * destination.
   *
   * <p>If the user cancels or provides no destination, the handler routes back to the welcome page
   * to keep the onboarding flow consistent. Otherwise, it sends a 302 response with a {@code
   * Location} header set to the requested external URL. The method does not rewrite or validate the
   * URL; upstream components remain responsible for escape rules and safety checks.
   *
   * @param uri request URI of this toadlet; must not be {@code null}.
   * @param request parsed HTTP request containing the posted form fields, notably {@link
   *     #MAGIC_HTTP_ESCAPE_STRING}.
   * @param ctx toadlet context used to write the redirect headers back to the client.
   * @throws ToadletContextClosedException if the client disconnects while headers are being sent or
   *     the context has already been disposed.
   * @throws IOException if writing the response fails for transport-level reasons.
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    Objects.requireNonNull(uri, "uri");
    String url = request.getPartAsStringFailsafe(MAGIC_HTTP_ESCAPE_STRING, MAX_URL_LENGTH);
    // If the user clicked cancel, or the URL is not defined, return to the main page.
    // Redirecting here restarts the welcome flow when it is still in progress; that behaviour is
    // intentional until the wizard gains partial-resume support.
    if (request.getPartAsStringFailsafe("Go", 32).isEmpty() || url.isEmpty()) {
      url = WelcomeToadlet.ROOT_PATH;
    }
    MultiValueTable<String, String> headers = MultiValueTable.from("Location", url);
    ctx.sendReplyHeaders(302, "Found", headers, null, 0);
  }

  /**
   * Renders a confirmation page warning users before leaving the local node's pages for an external
   * HTTP link.
   *
   * <p>The method requires a query parameter named {@link #MAGIC_HTTP_ESCAPE_STRING}; when missing
   * it redirects back to the welcome page to avoid issuing open redirects. When present, it
   * generates a warning infobox that shows the destination, offers cancel/continue buttons, and
   * optionally includes navigation/status bars if the setup wizard already completed. No network
   * access is attempted at this stage.
   *
   * @param uri request URI of this toadlet; must not be {@code null}.
   * @param request inbound HTTP request providing the external URL parameter and localization
   *     context.
   * @param ctx toadlet context used for building the page and writing the HTML response.
   * @throws ToadletContextClosedException if the connection closes before the response is fully
   *     written.
   * @throws IOException if rendering or sending the response fails.
   */
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    Objects.requireNonNull(uri, "uri");

    // Unexpected: a URL should have been specified.
    if (request.getParam(MAGIC_HTTP_ESCAPE_STRING).isEmpty()) {
      MultiValueTable<String, String> headers =
          MultiValueTable.from("Location", WelcomeToadlet.ROOT_PATH);
      ctx.sendReplyHeaders(302, "Found", headers, null, 0);
      return;
    }

    // Confirm whether the user really means to access an HTTP link.
    // Only render status and navigation bars if the user has completed the wizard.
    boolean renderBars = node.getClientCore().getToadletContainer().fproxyHasCompletedWizard();
    PageNode page =
        ctx.getPageMaker()
            .getPageNode(
                l10n("confirmExternalLinkTitle"),
                ctx,
                new RenderParameters().renderNavigationLinks(renderBars).renderStatus(renderBars));
    HTMLNode contentNode = page.getContentNode();
    HTMLNode warnboxContent =
        ctx.getPageMaker()
            .getInfobox(
                "infobox-warning",
                l10n("confirmExternalLinkSubTitle"),
                contentNode,
                "confirm-external-link",
                true);
    HTMLNode externalLinkForm =
        ctx.addFormChild(warnboxContent, EXTERNAL_LINK_PATH, "confirmExternalLinkForm");

    final String target = request.getParam(MAGIC_HTTP_ESCAPE_STRING);
    externalLinkForm.addChild("#", confirmExternalLinkText(target));
    externalLinkForm.addChild("br");
    externalLinkForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"hidden", MAGIC_HTTP_ESCAPE_STRING, target});
    externalLinkForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "cancel", NodeL10n.getBase().getString("Toadlet.cancel")});
    externalLinkForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "Go", l10n("goToExternalLink")});

    this.writeHTMLReply(ctx, 200, "OK", null, page.generate(), true);
  }

  /**
   * Prepends a given URI with the path and parameter names to get this external link confirmation
   * page.
   *
   * <p>The provided value is included as-is in the query string under {@link
   * #MAGIC_HTTP_ESCAPE_STRING}. Callers should supply an already-encoded URL segment to avoid
   * breaking the resulting link. The return value can be embedded directly into HTML anchors or
   * form actions within the node UI.
   *
   * @param uri URI to prompt for confirmation; should be percent-encoded and non-empty.
   * @return String appropriate for a link, combining {@link #EXTERNAL_LINK_PATH} and the escaped
   *     parameter.
   *     <pre>{@code
   * // Example: generate a confirmation URL for an external resource
   * String link = ExternalLinkToadlet.escape("https%3A%2F%2Fexample.org%2F");
   * }</pre>
   */
  public static String escape(String uri) {
    return ExternalLinkToadlet.EXTERNAL_LINK_PATH + "?" + MAGIC_HTTP_ESCAPE_STRING + '=' + uri;
  }

  private static String confirmExternalLinkText(String url) {
    return NodeL10n.getBase()
        .getString(
            "WelcomeToadlet.confirmExternalLinkWithURL", new String[] {"url"}, new String[] {url});
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("WelcomeToadlet." + key);
  }
}
