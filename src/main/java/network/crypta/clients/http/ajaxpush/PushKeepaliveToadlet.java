package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Receives AJAX-push keepalive requests for an existing push stream.
 *
 * <p>This toadlet implements a small HTTP endpoint used by the browser-side updater/long-poll
 * plumbing to indicate that a previously established push request is still active. The client
 * supplies a {@code requestId} parameter, which is forwarded to the owning {@link
 * network.crypta.clients.http.updateableelements.PushDataManager} via {@link
 * network.crypta.clients.http.SimpleToadletServer#getPushDataManager()}.
 *
 * <p>The endpoint deliberately responds with HTTP 200 in both the success and failure cases and
 * communicates the outcome via the response body ({@link
 * network.crypta.clients.http.updateableelements.UpdaterConstants#SUCCESS} or {@link
 * network.crypta.clients.http.updateableelements.UpdaterConstants#FAILURE}). A failure typically
 * means the {@code requestId} is no longer known (for example, it was already cleaned up).
 *
 * <ul>
 *   <li><b>Primary responsibility:</b> translate a keepalive HTTP request into a push-manager
 *       liveness signal.
 *   <li><b>Thread safety:</b> instances are stateless; concurrency properties depend on the
 *       container and push manager implementation.
 * </ul>
 *
 * @see network.crypta.clients.http.updateableelements.PushDataManager#keepAliveReceived(String)
 * @see network.crypta.clients.http.updateableelements.UpdaterConstants#keepalivePath
 */
public class PushKeepaliveToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(PushKeepaliveToadlet.class);

  /**
   * Creates a keepalive endpoint bound to the given client context.
   *
   * <p>The {@code HighLevelSimpleClient} is passed through to the {@link Toadlet} base class and is
   * used by shared toadlet infrastructure (for example, reply helpers and common request wiring).
   * This toadlet itself does not retain additional mutable state beyond what the superclass
   * maintains.
   *
   * @param client client context used by the {@link Toadlet} superclass; must be non-null
   */
  public PushKeepaliveToadlet(HighLevelSimpleClient client) {
    super(client);
  }

  /**
   * Handles an HTTP {@code GET} keepalive request for an existing push request.
   *
   * <p>The request is expected to include a {@code requestId} parameter, which identifies the push
   * request to keep alive. The identifier is forwarded to {@link
   * network.crypta.clients.http.updateableelements.PushDataManager#keepAliveReceived(String)} via
   * the {@link network.crypta.clients.http.SimpleToadletServer} container. The response is always
   * HTTP 200 with a small HTML body indicating success or failure; callers should treat the body as
   * the authoritative result rather than the status code.
   *
   * <p>This handler is typically safe to call repeatedly; it does not create new push requests, it
   * only refreshes liveness for an existing {@code requestId}. If the identifier is missing or no
   * longer recognized, the outcome depends on the push manager and is reported as a failure body.
   *
   * @param uri request URI for this toadlet invocation; supplied by the server and not modified
   * @param req HTTP request wrapper providing parameters such as {@code requestId}
   * @param ctx request context used to access the container and to write the HTTP response
   * @throws ToadletContextClosedException if the context closes before the response is written
   * @throws IOException if writing the response fails due to an underlying I/O problem
   * @throws RedirectException if the request must be redirected by the surrounding toadlet logic
   */
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    String requestId = req.getParam("requestId");
    if (LOG.isDebugEnabled()) {
      LOG.debug("Received push keepalive for requestId={}", requestId);
    }
    boolean success =
        ((SimpleToadletServer) ctx.getContainer())
            .getPushDataManager()
            .keepAliveReceived(requestId);
    if (success) {
      writeHTMLReply(ctx, 200, "OK", UpdaterConstants.SUCCESS);
    } else {
      writeHTMLReply(ctx, 200, "OK", UpdaterConstants.FAILURE);
    }
  }

  /**
   * Returns the HTTP path at which this toadlet is mounted.
   *
   * <p>The returned value is a stable constant used by the client-side updater to locate the
   * keepalive endpoint. It is not derived from runtime configuration.
   *
   * @return the keepalive endpoint path for AJAX push, as defined in {@link UpdaterConstants}
   */
  @Override
  public String path() {
    return UpdaterConstants.keepalivePath;
  }
}
