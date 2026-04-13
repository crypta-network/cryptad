package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.ContentToadlet;
import network.crypta.clients.http.PushUpdatableElement;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.Base64;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Serves the current rendered state of a pushed, updatable element.
 *
 * <p>This toadlet is part of the browser-side “AJAX push” mechanism: client-side JavaScript polls
 * {@link network.crypta.clients.http.updateableelements.UpdaterConstants#DATA_PATH} and expects the
 * server to return a compact payload describing how to update the DOM for a previously rendered
 * element. The request identifies both the page/request session and the specific element via query
 * parameters. The element identifier is expected to be Base64-like and therefore may contain {@code
 * '+'}; some clients decode {@code '+'} as a space when placed in a query string, so this endpoint
 * normalizes {@code ' '} back to {@code '+'} before looking up the element.
 *
 * <p>On success, the reply body is formatted as {@code SUCCESS:<type>:<children>} where {@code
 * <type>} is the UTF-8 Base64 encoding of {@link
 * network.crypta.clients.http.PushUpdatableElement#getUpdaterType()} and {@code <children>} is the
 * UTF-8 Base64 encoding of {@link
 * network.crypta.clients.http.PushUpdatableElement#generateChildren()}.
 *
 * <ul>
 *   <li>Responsibilities: translate request parameters into a rendered-element lookup and return a
 *       minimal update payload.
 *   <li>Thread-safety: this type is stateless per request; concurrency guarantees depend on the
 *       underlying {@link network.crypta.clients.http.updateableelements.PushDataManager}.
 * </ul>
 *
 * @see network.crypta.clients.http.updateableelements.PushDataManager
 * @see network.crypta.clients.http.PushUpdatableElement
 * @see network.crypta.clients.http.updateableelements.UpdaterConstants
 */
public class PushDataToadlet extends ContentToadlet {
  private static final Logger LOG = LoggerFactory.getLogger(PushDataToadlet.class);

  /**
   * Creates a new toadlet instance bound to the supplied high-level client helper.
   *
   * <p>The client is stored by the {@link network.crypta.clients.http.ContentToadlet} base class
   * and is available for toadlets that need to perform networked operations. This specific endpoint
   * only reads request parameters and queries the {@link
   * network.crypta.clients.http.updateableelements.PushDataManager}, but it follows the same
   * construction pattern as other toadlets and is typically registered with the toadlet container
   * during HTTP server initialization.
   *
   * @param client Non-null client helper provided by the node for toadlet operations.
   */
  public PushDataToadlet(HighLevelSimpleClient client) {
    super(client);
  }

  /**
   * Returns the current update payload for a previously rendered pushed element.
   *
   * <p>The handler expects two query parameters on {@code req}: {@code requestId} identifying the
   * request/session that rendered the element and {@code elementId} identifying the element within
   * that request. Because {@code elementId} may contain {@code '+'} characters (common in Base64),
   * the value is normalized by replacing spaces with {@code '+'} before the lookup. The element is
   * retrieved from the {@link network.crypta.clients.http.updateableelements.PushDataManager}
   * attached to the current {@link network.crypta.clients.http.SimpleToadletServer}.
   *
   * <p>On success, the method responds with HTTP {@code 200 OK} and a {@code text/html} body in the
   * format documented on the class. If the server cannot resolve the element, runtime failures may
   * occur (for example, a {@link NullPointerException} when dereferencing a missing element), which
   * is consistent with the historical behavior of this endpoint.
   *
   * <pre>{@code
   * // Example request shape:
   * // GET /pushdata/?requestId=<id>&elementId=<base64>
   * }</pre>
   *
   * @param uri Parsed request URI, currently unused by this handler but provided by the container.
   * @param req Parsed HTTP request providing query parameters for the lookup operation.
   * @param ctx Request context used to resolve the server container and write the reply.
   * @throws ToadletContextClosedException If the connection is closed while writing the response.
   * @throws IOException If writing, the response fails due to an I/O error.
   * @throws RedirectException If the container requests a redirect while processing this request.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    String requestId = req.getParam("requestId");
    String elementId = req.getParam("elementId");
    elementId =
        elementId.replace(
            " ", "+"); // This is needed because BASE64 has '+', but it is an HTML escape for ' '
    if (LOG.isDebugEnabled()) LOG.debug("Fetching push data for elementId={}", elementId);
    PushUpdatableElement node =
        ((SimpleToadletServer) ctx.getContainer())
            .getPushDataManager()
            .getRenderedElement(requestId, elementId);
    if (LOG.isDebugEnabled())
      LOG.debug("Fetched push data childrenHtml={}", node.generateChildren());
    writeHTMLReply(
        ctx,
        200,
        "OK",
        UpdaterConstants.SUCCESS
            + ":"
            + Base64.encodeStandard(node.getUpdaterType().getBytes(StandardCharsets.UTF_8))
            + ":"
            + Base64.encodeStandard(node.generateChildren().getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Returns the canonical HTTP mount path for this toadlet.
   *
   * <p>The returned value is used by the toadlet container for routing and by clients to locate the
   * endpoint that serves update payloads. The path is stable and defined by {@link
   * network.crypta.clients.http.updateableelements.UpdaterConstants#DATA_PATH}.
   *
   * @return The absolute path prefix under which this toadlet is reachable.
   */
  @Override
  public String path() {
    return UpdaterConstants.DATA_PATH;
  }
}
