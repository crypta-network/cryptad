package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;
import network.crypta.clients.http.BrowseContentClient;
import network.crypta.clients.http.ContentToadlet;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles the Ajax/Push “page leaving” notification from the web UI.
 *
 * <p>This toadlet provides a small HTTP endpoint that a browser page calls just before navigating
 * away or being unloaded. The handler extracts a {@code requestId} parameter from the request and
 * forwards it to the push-data subsystem so that server-side state associated with that request can
 * be released. This helps avoid retaining updateable element registrations, queued notifications,
 * or other per-page resources after the client is no longer present.
 *
 * <p><strong>Thread-safety:</strong> Instances are used by the toadlet server and may be invoked
 * concurrently for different connections. This class is effectively stateless; all mutable states
 * are owned by the container and its push-data manager.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Accepting a GET request on {@link #path()}.
 *   <li>Reading the request identifier from {@link HTTPRequest#getParam(String)}.
 *   <li>Notifying the server that the client has left and returning a small success body.
 * </ul>
 *
 * @see UpdaterConstants#LEAVING_PATH
 */
public class PushLeavingToadlet extends ContentToadlet {
  private static final Logger LOG = LoggerFactory.getLogger(PushLeavingToadlet.class);

  /**
   * Creates a toadlet instance that can be registered on a {@link SimpleToadletServer}.
   *
   * <p>The provided client is forwarded to the {@link ContentToadlet} base type and is used for
   * common toadlet functionality. This implementation does not store additional mutable state;
   * request handling delegates to the container's push-data manager obtained from the {@link
   * ToadletContext} provided at request time.
   *
   * @param client the node client backing this toadlet, passed to the superclass for shared
   *     services and request handling support
   */
  public PushLeavingToadlet(BrowseContentClient client) {
    super(client);
  }

  /**
   * Handles the HTTP GET request that signals that a browser page is leaving.
   *
   * <p>This endpoint expects a {@code requestId} parameter identifying the page/session to clean
   * up. The implementation forwards the identifier to the push-data manager so that associated
   * server-side registrations and pending notifications can be discarded. On success, it responds
   * with an {@code 200 OK} and the {@link UpdaterConstants#SUCCESS} body, regardless of whether any
   * state existed for the provided identifier.
   *
   * @param uri the request URI for this toadlet invocation, used for routing and logging context
   * @param req the HTTP request providing the {@code requestId} parameter and any other metadata
   * @param ctx the per-request toadlet context used to access the container and write the response
   * @throws ToadletContextClosedException if the connection closes while writing the response
   * @throws IOException if generating or sending the response fails due to I/O problems
   * @throws RedirectException if the framework requires redirecting this request to another
   *     location
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    String requestId = req.getParam("requestId");
    boolean deleted =
        ((SimpleToadletServer) ctx.getContainer()).getPushDataManager().leaving(requestId);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Client left page (requestId={}, deleted={})", requestId, deleted);
    }
    writeHTMLReply(ctx, 200, "OK", UpdaterConstants.SUCCESS);
  }

  /**
   * Returns the fixed server path for “page leaving” notifications.
   *
   * <p>The returned value is a constant route used by the web UI to notify the node that a page is
   * no longer active. Callers should treat this value as an opaque, versioned endpoint identifier
   * and avoid hard-coding a separate copy; using this method keeps routing consistent with the
   * updater/push subsystem.
   *
   * @return the HTTP path that maps to this toadlet, typically {@link
   *     UpdaterConstants#LEAVING_PATH}
   */
  @Override
  public String path() {
    return UpdaterConstants.LEAVING_PATH;
  }
}
