package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;
import network.crypta.clients.http.BrowseContentClient;
import network.crypta.clients.http.ContentToadlet;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.clients.http.PageNode;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.TesterElement;
import network.crypta.support.api.HTTPRequest;

/**
 * A small {@link Toadlet} that serves a deterministic page containing push-capable test elements.
 *
 * <p>This endpoint is intentionally minimal: it constructs a single HTML page and injects a fixed
 * number of {@link TesterElement} instances into the page content. The primary use is automated or
 * manual verification of the Ajax push/updateable-elements plumbing (rendering, incremental
 * updates, and client-side consumption) without having to navigate through unrelated UI flows.
 *
 * <p>The implementation is deliberately deterministic: it always produces 600 elements with stable,
 * numeric ids ("0" through "599") and a fixed per-element configuration value. The instance itself
 * is effectively stateless; request-specific state is carried by the provided {@link
 * ToadletContext} and the element implementations.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Disables navigation links in the rendered page template to reduce unrelated markup churn.
 *   <li>Returns an {@code HTTP 200} response with a simple {@code OK} status message.
 *   <li>Constructs elements eagerly during request handling; there is no caching across requests.
 * </ul>
 *
 * @see TesterElement
 */
public class PushTesterToadlet extends ContentToadlet {

  /**
   * Creates a new instance that serves the push-test page.
   *
   * <p>The provided {@link BrowseContentClient} is forwarded to the {@link ContentToadlet}
   * superclass. This class does not retain additional mutable state, so instances are safe to reuse
   * across requests as long as the surrounding toadlet container provides the usual per-request
   * {@link ToadletContext}.
   *
   * @param client client instance passed to the {@link ContentToadlet} superclass; must be non-null
   *     and configured
   */
  public PushTesterToadlet(BrowseContentClient client) {
    super(client);
  }

  /**
   * Handles {@code GET} requests by emitting a page populated with a fixed set of {@link
   * TesterElement} instances.
   *
   * <p>This method creates a page titled {@code Push tester} with navigation links disabled, then
   * adds 600 elements to the page content. Each element id is the decimal string of its index (from
   * {@code "0"} through {@code "599"}), and each is constructed with a fixed configuration value of
   * {@code 100} as required by the {@link TesterElement} constructor.
   *
   * <p>The response is written immediately via {@code writeHTMLReply(...)} using a {@code 200}
   * status code and an {@code OK} message. The method does not mutate instance state; any request
   * lifecycle, threading, or streaming concerns are handled by {@code ctx} and the underlying HTTP
   * server.
   *
   * @param uri request URI, used for routing and diagnostics by the surrounding toadlet framework
   * @param req parsed HTTP request wrapper, providing access to headers and request metadata as
   *     needed
   * @param ctx per-request context used to build the page and write the HTTP response to the client
   * @throws ToadletContextClosedException if the HTTP context closes before or while the reply is
   *     written
   * @throws IOException if an I/O error occurs while generating or writing the HTML response body
   * @throws RedirectException if the framework requests a redirect instead of sending a direct
   *     reply
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    PageNode pageNode =
        ctx.getPageMaker()
            .getPageNode("Push tester", ctx, new RenderParameters().renderNavigationLinks(false));
    for (int i = 0; i < 600; i++) {
      pageNode.getContentNode().addChild(new TesterElement(ctx, String.valueOf(i), 100));
    }
    writeHTMLReply(ctx, 200, "OK", pageNode.generate());
  }

  /**
   * Returns the HTTP path prefix that routes requests to this test endpoint.
   *
   * <p>The returned value is a fixed, absolute path and includes a trailing slash to match typical
   * toadlet routing conventions.
   *
   * @return the path prefix for the push-tester toadlet, always {@code "/pushtester/"}
   */
  @Override
  public String path() {
    return "/pushtester/";
  }
}
