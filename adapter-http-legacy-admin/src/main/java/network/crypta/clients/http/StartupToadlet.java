package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * Serves the transient "Freenet is starting up" status page during node boot.
 *
 * <p>This toadlet responds on the root path while the node is still initializing, replacing the
 * normal UI with a lightweight progress page that refreshes automatically until the full interface
 * is ready. It delegates static assets to {@link StaticToadlet} when the requested path is under
 * the shared static prefix so images and styles remain available even before startup completes. The
 * handler always forces the HTTP connection to close to avoid keep-alive issues with incomplete
 * initialization.
 *
 * <p>The page shows an entropy warning until the PRNG reports readiness via {@link
 * #setIsPRNGReady()}; this guards against low-entropy environments during early boot. A
 * meta-refresh controls the retry cadence instead of HTTP headers, keeping behavior consistent
 * across intermediaries. The class is thread-safe for the readiness flag because the field is
 * {@code volatile}, and it assumes the surrounding {@link Toadlet} infrastructure provides any
 * broader synchronization needed for request handling.
 *
 * <ul>
 *   <li>Responsibilities: render startup status, surface entropy readiness, proxy static assets.
 *   <li>Lifecycle: active only during bootstrap, replaced by the normal UI when the node is ready.
 *   <li>Concurrency: stateless per request; a readiness flag may be set from background threads.
 * </ul>
 */
public class StartupToadlet extends Toadlet {

  private final StaticToadlet staticToadlet;
  private volatile boolean isPRNGReady = false;

  /**
   * Creates a startup toadlet that can optionally delegate static content during bootstrap.
   *
   * <p>The provided {@link StaticToadlet} is used only when the incoming request path begins with
   * {@link StaticToadlet#ROOT_URL}, allowing shared CSS or images to load while the main UI waits
   * for initialization. Callers typically wire this from the HTTP router at node startup and keep
   * it registered until the normal UI replaces the startup handler.
   *
   * @param staticToadlet optional handler for static resources; may be {@code null} if delegation
   *     is not needed during startup.
   */
  public StartupToadlet(StaticToadlet staticToadlet) {
    super(null);
    this.staticToadlet = staticToadlet;
  }

  /**
   * Handles GET requests for the startup page and delegates static assets when appropriate.
   *
   * <p>The method forces the connection to close to avoid HTTP pipelining during initialization,
   * then serves either delegated static content or a minimal status page that refreshes every
   * second. The status page embeds an entropy warning until {@link #setIsPRNGReady()} is invoked,
   * displays a short startup message, and optionally links wrapper logs for troubleshooting. The
   * response uses status {@code 503} with an HTML body so clients retry naturally without relying
   * on HTTP {@code Retry-After} headers.
   *
   * <pre>{@code
   * // Example: invoked by the HTTP server during bootstrap
   * startupToadlet.handleMethodGET(uri, request, context);
   * }</pre>
   *
   * @param uri request URI already parsed by the HTTP layer; path guides static delegation.
   * @param req inbound HTTP request containing parameters and headers; must not be {@code null}.
   * @param ctx toadlet context providing page builders and reply helpers; must be open for writes.
   * @throws ToadletContextClosedException if the context has been closed before writing the reply.
   * @throws IOException if page generation or output streaming fails while sending the response.
   * @throws RedirectException if the handler requests a redirect instead of rendering the page.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    // If we don't disconnect, we will have pipelining issues
    ctx.forceDisconnect();

    String path = uri.getPath();
    if (path.startsWith(StaticToadlet.ROOT_URL) && staticToadlet != null)
      staticToadlet.handleMethodGET(uri, req, ctx);
    else {
      String desc = NodeL10n.getBase().getString("StartupToadlet.title");
      PageNode page =
          ctx.getPageMaker()
              .getPageNode(
                  desc,
                  ctx,
                  new RenderParameters()
                      .renderStatus(false)
                      .renderNavigationLinks(false)
                      .renderModeSwitch(false));
      HTMLNode headNode = page.getHeadNode();
      headNode.addChild(
          "meta", new String[] {"http-equiv", "content"}, new String[] {"refresh", "1; url="});
      HTMLNode contentNode = page.getContentNode();

      if (!isPRNGReady) {
        HTMLNode prngInfoboxContent =
            ctx.getPageMaker()
                .getInfobox(
                    "infobox-error",
                    NodeL10n.getBase().getString("StartupToadlet.entropyErrorTitle"),
                    contentNode,
                    null,
                    true);
        prngInfoboxContent.addChild(
            "#", NodeL10n.getBase().getString("StartupToadlet.entropyErrorContent"));
      }

      HTMLNode infoboxContent =
          ctx.getPageMaker().getInfobox("infobox-error", desc, contentNode, null, true);
      infoboxContent.addChild("#", NodeL10n.getBase().getString("StartupToadlet.isStartingUp"));

      LegacyWelcomePageSupport.maybeDisplayWrapperLogfile(ctx, contentNode);

      // Retry cadence is controlled via meta-refresh rather than HTTP header.
      writeHTMLReply(ctx, 503, desc, page.generate());
    }
  }

  /**
   * Marks the node's pseudo-random number generator as ready to suppress entropy warnings.
   *
   * <p>This flag is intended to be invoked by whichever component monitors entropy availability
   * during startup (for example, once a secure PRNG has seeded). Because the field is {@code
   * volatile}, updates become visible to later HTTP requests without additional synchronization.
   * Callers should set this only once the PRNG is genuinely usable to avoid misleading the startup
   * page about entropy quality.
   */
  public void setIsPRNGReady() {
    isPRNGReady = true;
  }

  /**
   * Returns the URL path served by this toadlet while the node is starting up.
   *
   * <p>The startup handler is registered on the root path, so it intercepts all incoming requests
   * until the main UI replaces it after initialization completes. Keeping the path fixed ensures
   * clients that attempt to reach {@code /} receive a consistent status page rather than a socket
   * error during the transition. The string is immutable and safe to cache by routing layers.
   *
   * @return the literal root path {@code "/"} used to register the startup toadlet.
   */
  @Override
  public String path() {
    return "/";
  }
}
