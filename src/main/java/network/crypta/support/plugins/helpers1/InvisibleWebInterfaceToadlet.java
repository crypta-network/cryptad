package network.crypta.support.plugins.helpers1;

import java.io.IOException;
import java.net.URI;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.support.api.HTTPRequest;

/**
 * Web UI toadlet wrapper that exposes another toadlet without adding visible UI elements.
 *
 * <p>This implementation is used by plugins that need to register a {@link Toadlet} in the node's
 * HTTP stack but do not want the toadlet to appear as a standalone web interface. It delegates
 * visibility decisions to {@link #showAsToadlet(ToadletContext)} while retaining the core behavior
 * from {@link WebInterfaceToadlet}. Typical usage is to construct an instance during plugin setup,
 * register it with the hosting {@link PluginContext}, and then override {@link
 * #handleMethodGET(URI, HTTPRequest, ToadletContext)} in a subclass to provide actual content.
 *
 * <p>State is immutable after construction. The instance is thread-safe under the same assumptions
 * as {@link WebInterfaceToadlet}; it holds only a reference to the delegate toadlet and otherwise
 * relies on the HTTP framework for concurrency guarantees. The trade-off is that unimplemented
 * request handlers return an error response, so callers must override the GET handler for real
 * output.
 *
 * <ul>
 *   <li>Delegates UI exposure to a provided toadlet instance.
 *   <li>Provides a safe default GET handler that returns an error page.
 *   <li>Designed for plugin helpers where UI visibility is controlled elsewhere.
 * </ul>
 *
 * @see WebInterfaceToadlet
 * @see PluginContext
 */
@SuppressWarnings("unused")
public class InvisibleWebInterfaceToadlet extends WebInterfaceToadlet {

  private final Toadlet showAsToadlet;

  /**
   * Creates an invisible web interface wrapper for plugin routing.
   *
   * <p>The constructed toadlet is registered like any other {@link WebInterfaceToadlet} but will
   * report the supplied delegate when the HTTP layer asks which UI to show. This lets plugins reuse
   * an existing {@link Toadlet} for display decisions while keeping the handler class itself
   * invisible in menus or listings. The provided fields are stored directly and are not mutated
   * later, so callers should supply stable objects that remain valid for the lifetime of the
   * toadlet.
   *
   * @param pluginContext2 plugin context that owns the registration and lifecycle coordination
   * @param pluginURL2 base URL segment under which the toadlet is mounted in HTTP paths
   * @param pageName2 human-readable page name used for diagnostics and registration metadata
   * @param showAsToadlet delegate used to decide UI exposure; may be {@code null}
   */
  protected InvisibleWebInterfaceToadlet(
      PluginContext pluginContext2, String pluginURL2, String pageName2, Toadlet showAsToadlet) {
    super(pluginContext2, pluginURL2, pageName2);
    this.showAsToadlet = showAsToadlet;
  }

  /**
   * Returns the toadlet that should be treated as the visible UI representative.
   *
   * <p>The HTTP layer calls this method when determining whether the current toadlet should appear
   * in UI listings. The returned object is not modified; it is simply forwarded as-is. If {@code
   * null} is returned, callers should treat this toadlet as having no visible UI representation.
   *
   * @param context active request context used for visibility decisions, typically non-null
   * @return the delegate toadlet to show instead, or {@code null} for no UI surface
   */
  @Override
  public Toadlet showAsToadlet(ToadletContext context) {
    return showAsToadlet;
  }

  /**
   * Handles HTTP GET requests with a default error response.
   *
   * <p>This base implementation exists solely to avoid silent failures when subclasses do not
   * provide a handler. It responds with an internal error page indicating that the handler is not
   * implemented. Subclasses are expected to override this method and generate the desired content
   * while preserving the same exception contract. The method does not alter the state beyond
   * emitting the response.
   *
   * @param uri requested URI including path and query components for the incoming request
   * @param request parsed HTTP request wrapper supplying parameters and body data
   * @param ctx request context used to write the response and manage connection state
   * @throws ToadletContextClosedException if the client disconnects while writing the response
   * @throws IOException if the response cannot be written to the underlying stream
   * @throws RedirectException if a subclass chooses to perform a redirect instead
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    this.sendErrorPage(ctx, 500, "Internal Server Error", "Not implemented");
  }
}
