package network.crypta.platform.webshell;

import java.util.Objects;
import network.crypta.platform.webshell.bootstrap.WebShellBootstrap;
import network.crypta.platform.webshell.bootstrap.WebShellBootstrapJson;
import network.crypta.platform.webshell.routes.WebShellPaths;

/**
 * Renders the Web Shell v1 HTML page from the shell-owned resource template.
 *
 * <p>This renderer is the last leaf-owned step before the legacy HTTP adapter sends the shell page
 * to a browser. It keeps the page assembly deliberately small: load one static HTML template, turn
 * the shell bootstrap model into stable JSON, and splice that JSON into the placeholder consumed by
 * the browser bootstrap script. The class does not know about HTTP headers, access control, or
 * runtime node state. That split keeps the platform web-shell leaf transport-neutral and lets the
 * adapter remain a thin bridge instead of growing a second browser templating system.
 *
 * <p>The template is cached as plain text from the classpath, so repeated renders only pay the cost
 * of serializing the bootstrap payload and replacing the placeholder token. For the current shell
 * this is enough, predictable, and easy to test without introducing a server-side view engine.
 */
public final class WebShellPageRenderer {
  /** Placeholder token replaced with the bootstrap JSON payload. */
  private static final String BOOTSTRAP_PLACEHOLDER = "__BOOTSTRAP_JSON__";

  /** Cached shell template loaded from the classpath. */
  private static final String TEMPLATE =
      WebShellResources.readText(WebShellPaths.INDEX_RESOURCE_PATH);

  /** Prevents instantiation of this static rendering helper. */
  private WebShellPageRenderer() {}

  /**
   * Renders the Web Shell HTML page for the supplied bootstrap data.
   *
   * <p>The returned document is ready for the adapter to serve as the shell entry page. The
   * bootstrap payload is serialized exactly once and inserted into the template's inline bootstrap
   * slot, which lets the browser discover route roots and legacy deep links without making a
   * separate bootstrap request. Callers should treat the returned string as a complete HTML
   * document, not as a fragment to concatenate with additional markup.
   *
   * @param bootstrap browser bootstrap payload to inject into the template
   * @return final HTML page ready for transport through the legacy HTTP bridge
   * @throws NullPointerException if {@code bootstrap} is {@code null}
   */
  public static String render(WebShellBootstrap bootstrap) {
    Objects.requireNonNull(bootstrap, "bootstrap");
    return TEMPLATE.replace(BOOTSTRAP_PLACEHOLDER, WebShellBootstrapJson.serialize(bootstrap));
  }
}
