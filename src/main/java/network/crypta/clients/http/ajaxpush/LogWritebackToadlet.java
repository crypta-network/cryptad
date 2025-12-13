package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.URLDecoder;
import network.crypta.support.URLEncodedFormatException;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Receives client-side log messages and forwards them to the node logger.
 *
 * <p>This toadlet exists primarily as a low-friction bridge for web UI components (for example,
 * Ajax-driven pages) to report diagnostics back to the server-side log stream during development or
 * troubleshooting. The endpoint accepts an HTTP GET request containing a single query parameter
 * named {@code msg}. When server-side debug logging is enabled for this class, the handler decodes
 * the parameter as a raw percent-encoded URI component via {@link URLDecoder} (not {@code
 * application/x-www-form-urlencoded}) and emits the decoded content as a debug log line.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Logging is conditional: when debug logging is disabled, the message is ignored and only the
 *       success reply is returned.
 *   <li>Malformed percent-escapes are handled defensively: the undecoded {@code msg} value is
 *       logged at error level, and the request still receives a successful response.
 *   <li>The HTTP response body is always {@link UpdaterConstants#SUCCESS} with status {@code 200
 *       OK}; this endpoint is intended for fire-and-forget client usage.
 * </ul>
 *
 * <p>Thread-safety: instances are stateless and safe to reuse concurrently as long as the
 * surrounding {@link Toadlet} infrastructure is used as intended.
 */
public class LogWritebackToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(LogWritebackToadlet.class);

  /**
   * Creates a new instance bound to the provided high-level client helper.
   *
   * <p>The client is required by the {@link Toadlet} base type even though this particular endpoint
   * does not perform network fetches or inserts. Callers typically construct this once and register
   * it with the HTTP container that routes requests based on {@link #path()}.
   *
   * @param client non-null client helper retained by the base {@link Toadlet}; unused by this
   *     implementation but required for consistent wiring and future compatibility
   */
  public LogWritebackToadlet(HighLevelSimpleClient client) {
    super(client);
  }

  /**
   * Handles a client log writeback request.
   *
   * <p>This handler reads {@code msg} from the supplied {@link HTTPRequest} and, when debug logging
   * is enabled, attempts to decode it using {@link URLDecoder#decode(String, boolean)} with {@code
   * tolerant=false}. If decoding succeeds, the decoded message is logged at debug level; if it
   * fails with {@link URLEncodedFormatException}, the raw parameter value is logged as an error.
   *
   * <p>Regardless of logging outcome, the handler sends an HTML response with status {@code 200},
   * reason phrase {@code "OK"}, and body {@link UpdaterConstants#SUCCESS}. The method is intended
   * to be idempotent: repeated calls with the same input do not change server state beyond
   * producing log output.
   *
   * @param uri request URI passed by the container; not used by this handler but provided for
   *     consistency with other toadlets and potential future use
   * @param req parsed HTTP request providing query parameters; {@code msg} is read via {@link
   *     HTTPRequest#getParam(String)} and defaults to an empty string when missing
   * @param ctx response context used to write the {@code 200 OK} success reply; must be open when
   *     called or a close exception is thrown by the context implementation
   * @throws ToadletContextClosedException if the client disconnects before the success reply can be
   *     written to the {@link ToadletContext}
   * @throws IOException if writing the response fails due to an underlying I/O error
   * @throws RedirectException declared for the base dispatch contract; this implementation does not
   *     initiate redirects
   */
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (LOG.isDebugEnabled()) {
      try {
        LOG.debug("GWT:{}", URLDecoder.decode(req.getParam("msg"), false));
      } catch (URLEncodedFormatException e) {
        LOG.error("Invalid GWT:{}", req.getParam("msg"));
      }
    }
    writeHTMLReply(ctx, 200, "OK", UpdaterConstants.SUCCESS);
  }

  /**
   * Returns the mount path for this toadlet.
   *
   * <p>The HTTP container uses this value to route incoming requests and to build links. The path
   * is a stable constant defined in {@link UpdaterConstants} so both client-side scripts and
   * server-side code refer to the same endpoint.
   *
   * @return the absolute path fragment under which this toadlet is served, typically {@code
   *     "/logwriteback/"}
   */
  @Override
  public String path() {
    return UpdaterConstants.logWritebackPath;
  }
}
