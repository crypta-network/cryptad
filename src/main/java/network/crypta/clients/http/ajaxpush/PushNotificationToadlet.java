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
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Long-poll endpoint that delivers the next pending AJAX push notification for a client.
 *
 * <p>This {@link Toadlet} is used by the browser-side update mechanism to wait for an event and
 * then return a compact, machine-readable payload. Callers typically issue a GET request to {@link
 * #path()} with a {@code requestId} parameter; the handler consults the {@link PushDataManager}
 * from the current {@link SimpleToadletServer} and blocks until the next {@link
 * PushDataManager.UpdateEvent} becomes available for that request.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Uses long-poll semantics: it may block until an event arrives or the request context
 *       closes.
 *   <li>Returns either a success payload containing identifiers, or a failure sentinel string.
 *   <li>Performs no state mutation itself; it delegates event sequencing to {@link
 *       PushDataManager}.
 * </ul>
 *
 * <p>Thread-safety: instances are expected to be invoked concurrently by the HTTP server; this
 * implementation performs only local computations and relies on {@link PushDataManager} for
 * synchronization and ordering.
 *
 * @see PushDataManager#getNextNotification(String)
 * @see UpdaterConstants#NOTIFICATION_PATH
 */
public class PushNotificationToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(PushNotificationToadlet.class);

  /**
   * Create a toadlet bound to a client context.
   *
   * <p>The provided client is passed to the parent {@link Toadlet} and is used for shared
   * HTTP/toadlet infrastructure. This class does not retain additional mutable state, so a single
   * instance can serve multiple requests over its lifetime as managed by the server.
   *
   * @param client client context used by the toadlet framework; must be non-null for normal
   *     operation
   */
  public PushNotificationToadlet(HighLevelSimpleClient client) {
    super(client);
  }

  /**
   * Wait for and return the next notification event for the given long-poll request.
   *
   * <p>This handler reads the {@code requestId} query parameter from {@code req} and forwards it to
   * {@link PushDataManager#getNextNotification(String)}. When an event is available, it returns a
   * success payload composed of the event's request identifier and element identifier; otherwise it
   * returns a failure sentinel value. The response body is intended to be parsed by the
   * browser-side updater logic and is not meant for direct human consumption.
   *
   * <p>The method may block while waiting for an event. If the request context closes while
   * blocked, {@link ToadletContextClosedException} can be thrown by the underlying server
   * infrastructure.
   *
   * @param uri request URI associated with this call; currently unused but provided by the
   *     framework
   * @param req HTTP request carrying query parameters such as {@code requestId}; must be non-null
   * @param ctx request context used to write the reply; must be open for the duration of the call
   * @throws ToadletContextClosedException if the client disconnects or the context closes during
   *     handling
   * @throws IOException if writing the HTTP response fails due to an underlying I/O error
   * @throws RedirectException if the framework requires a redirect response for this request
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    String requestId = req.getParam("requestId");
    PushDataManager.UpdateEvent event =
        ((SimpleToadletServer) ctx.getContainer())
            .getPushDataManager()
            .getNextNotification(requestId);
    if (event != null) {
      String elementRequestId = event.getRequestId();
      String elementId = event.getElementId();
      writeHTMLReply(
          ctx,
          200,
          "OK",
          UpdaterConstants.SUCCESS
              + ":"
              + Base64.encodeStandard(elementRequestId.getBytes(StandardCharsets.UTF_8))
              + UpdaterConstants.SEPARATOR
              + elementId);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Notification got: {}", event);
      }
    } else {
      writeHTMLReply(ctx, 200, "OK", UpdaterConstants.FAILURE);
    }
  }

  /**
   * Return the HTTP path that routes requests to this toadlet.
   *
   * <p>The returned value is a stable server-side constant used by the AJAX push client code to
   * construct the notification polling URL.
   *
   * @return the configured notification endpoint path for this toadlet
   */
  @Override
  public String path() {
    return UpdaterConstants.NOTIFICATION_PATH;
  }
}
