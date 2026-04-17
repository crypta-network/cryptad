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
 * Handles push-leader failover for the AJAX push subsystem.
 *
 * <p>This toadlet implements a small HTTP endpoint used by the browser-side “AJAX push” code when
 * leadership for a page/session changes. In that situation, outstanding update notifications
 * waiting on the previous leader request may need to be reassigned to the new leader request so
 * polling continues without losing queued updates.
 *
 * <p>The handler reads two query parameters from the incoming request: {@code originalRequestId}
 * (the request id that previously acted as leader) and {@code requestId} (the request id that is
 * taking over). It then delegates to {@link
 * network.crypta.clients.http.updateableelements.PushDataManager#failover(String, String)} via the
 * {@link network.crypta.clients.http.SimpleToadletServer} container. The response body is a simple
 * success/failure token defined by {@link
 * network.crypta.clients.http.updateableelements.UpdaterConstants} and is suitable for use by
 * lightweight client-side scripts.
 *
 * <ul>
 *   <li>Responsibilities: translate request parameters into a {@code PushDataManager} failover call
 *       and return a compact status response.
 *   <li>Thread-safety: this type is stateless per request; concurrency guarantees depend on the
 *       synchronized {@code PushDataManager} implementation.
 * </ul>
 *
 * @see network.crypta.clients.http.updateableelements.PushDataManager#failover(String, String)
 * @see network.crypta.clients.http.ajaxpush.PushDataToadlet
 * @see network.crypta.clients.http.ajaxpush.PushNotificationToadlet
 */
public class PushFailoverToadlet extends ContentToadlet {
  private static final Logger LOG = LoggerFactory.getLogger(PushFailoverToadlet.class);

  /**
   * Creates a new toadlet instance bound to the supplied high-level client helper.
   *
   * <p>The {@link network.crypta.clients.http.ContentToadlet} base class stores the client
   * reference for use by endpoints that need to perform node-backed operations. This specific
   * toadlet delegates to the {@link network.crypta.clients.http.updateableelements.PushDataManager}
   * attached to the active {@link network.crypta.clients.http.SimpleToadletServer}, but it follows
   * the same construction pattern as the rest of the HTTP toadlets and is typically registered
   * during HTTP server startup.
   *
   * @param client Non-null client helper provided by the node for toadlet operations.
   */
  public PushFailoverToadlet(BrowseContentClient client) {
    super(client);
  }

  /**
   * Performs push failover by moving queued notifications from one request id to another.
   *
   * <p>The request must provide the {@code originalRequestId} query parameter identifying the
   * request/session that previously acted as the leader and the {@code requestId} query parameter
   * identifying the new leader request. The method delegates to {@link
   * network.crypta.clients.http.updateableelements.PushDataManager#failover(String, String)} and
   * writes a {@code 200 OK} response whose body is either {@link
   * network.crypta.clients.http.updateableelements.UpdaterConstants#SUCCESS} or {@link
   * network.crypta.clients.http.updateableelements.UpdaterConstants#FAILURE}.
   *
   * <p>This endpoint does not perform additional validation of the supplied ids. If the underlying
   * manager cannot perform the reassignment (for example, because the original id is unknown), the
   * result is reported as {@code FAILURE} while still returning HTTP {@code 200 OK}.
   *
   * <pre>{@code
   * // Example request shape:
   * // GET /pushfailover/?originalRequestId=<old>&requestId=<new>
   * }</pre>
   *
   * @param uri Parsed request URI, currently unused by this handler but provided by the container.
   * @param req Parsed HTTP request providing the failover query parameters.
   * @param ctx Request context used to resolve the server container and write the reply.
   * @throws ToadletContextClosedException If the connection is closed while writing the response.
   * @throws IOException If writing, the response fails due to an I/O error.
   * @throws RedirectException If the container requests a redirect while processing this request.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    String requestId = req.getParam("requestId");
    String originalRequestId = req.getParam("originalRequestId");
    boolean result =
        ((SimpleToadletServer) ctx.getContainer())
            .getPushDataManager()
            .failover(originalRequestId, requestId);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Failover from:{} to:{} with result:{}", originalRequestId, requestId, result);
    }
    writeHTMLReply(ctx, 200, "OK", result ? UpdaterConstants.SUCCESS : UpdaterConstants.FAILURE);
  }

  /**
   * Returns the canonical HTTP mount path for this toadlet.
   *
   * <p>The returned value is used by the toadlet container for routing and by clients to locate the
   * endpoint that triggers a {@code PushDataManager} failover. The path is stable and defined by
   * {@link network.crypta.clients.http.updateableelements.UpdaterConstants#FAILOVER_PATH}.
   *
   * @return The absolute path prefix under which this toadlet is reachable.
   */
  @Override
  public String path() {
    return UpdaterConstants.FAILOVER_PATH;
  }
}
