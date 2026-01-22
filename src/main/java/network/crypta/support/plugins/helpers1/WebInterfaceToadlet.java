package network.crypta.support.plugins.helpers1;

import java.util.List;
import network.crypta.clients.http.InfoboxNode;
import network.crypta.clients.http.LinkEnabledCallback;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.pluginmanager.PluginRespirator;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * Base toadlet for plugin web interfaces with shared helpers for path handling and error
 * presentation.
 *
 * <p>This class centralizes small utilities that most plugin toadlets need: it preserves the
 * resolved path prefix, provides a consistent path normalization routine for dispatching subpaths,
 * validates form-password submissions for state-changing requests, and builds a simple error
 * infobox for HTML responses. Subclasses typically register the toadlet with a plugin URL prefix
 * and then implement their own GET/POST handlers using these helpers to reduce boilerplate.
 *
 * <p>The class is effectively immutable after construction, but it exposes the shared {@link
 * PluginContext} which is mutable and owned by the plugin runtime. Thread-safety therefore depends
 * on the underlying toadlet lifecycle and the services exposed by {@link PluginContext}; this class
 * does not add synchronization.
 *
 * <ul>
 *   <li>Stores the resolved toadlet path and exposes it via {@link #path()}.
 *   <li>Normalizes request paths to stable, comparable suffixes.
 *   <li>Builds standard error infoboxes with optional retry links.
 * </ul>
 *
 * @see PluginContext
 * @see PluginRespirator
 */
public abstract class WebInterfaceToadlet extends Toadlet implements LinkEnabledCallback {

  /**
   * Shared plugin services used by the toadlet for page building and security checks.
   *
   * <p>The reference is immutable, but the services it exposes may be mutable and are owned by the
   * plugin runtime. Callers should not assume thread-safety beyond what those services provide.
   */
  protected final PluginContext pluginContext;

  private static final char PATH_SEPARATOR = '/';

  private final String toadletPath;

  /**
   * Constructs a new web-interface toadlet with a resolved path prefix.
   *
   * <p>The resulting path is built from the plugin URL prefix and the page name. The value is
   * computed once and reused for all requests, so callers should ensure the inputs are stable and
   * already normalized to the desired base path.
   *
   * @param pluginContext2 plugin runtime services used for page and security helpers; must be
   *     non-null and valid for the toadlet lifetime
   * @param pluginURL plugin base URL prefix that anchors this toadlet; non-null and typically
   *     already rooted at the plugin mount point
   * @param pageName page path segment appended to the plugin URL; non-null and not expected to
   *     contain trailing separators
   */
  protected WebInterfaceToadlet(PluginContext pluginContext2, String pluginURL, String pageName) {
    super(pluginContext2.hlsc);
    pluginContext = pluginContext2;
    toadletPath = pluginURL + PATH_SEPARATOR + pageName;
  }

  /**
   * Returns the full, resolved path prefix for this toadlet.
   *
   * <p>The returned value is stable for the lifetime of the instance and includes the plugin URL
   * prefix plus the page name supplied to the constructor. The method has no side effects and never
   * returns {@code null}.
   *
   * @return resolved toadlet path used for request routing and link construction
   */
  @Override
  public String path() {
    return toadletPath;
  }

  /**
   * Reports whether this toadlet is enabled for the supplied context.
   *
   * <p>This implementation always returns {@code true} and ignores the context. Subclasses may
   * override when they need dynamic enablement based on context, permissions, or configuration.
   *
   * @param ctx request context associated with the current HTTP handling; may be ignored
   * @return {@code true} to indicate the toadlet should be available for handling requests
   */
  @Override
  public boolean isEnabled(ToadletContext ctx) {
    return true;
  }

  /**
   * Normalizes a request path to a stable suffix relative to this toadlet.
   *
   * <p>The input is expected to start with {@link #path()} and represent a request URI path. The
   * returned value omits the toadlet prefix and trims exactly one trailing {@code '/'} character,
   * so {@code "/foo"} and {@code "/foo/"} are normalized to the same suffix. If the suffix is
   * empty, this method returns {@code "/"} to provide a consistent root marker.
   *
   * @param path full request path starting with this toadlet prefix; must be at least the prefix
   *     length
   * @return normalized suffix without the toadlet prefix, or {@code "/"} for the root
   */
  @SuppressWarnings("unused")
  protected String normalizePath(String path) {
    String result = path.substring(toadletPath.length());
    if (result.isEmpty()) {
      return "/";
    }
    if (result.endsWith("/")) {
      result = result.substring(0, result.length() - 1);
    }
    return result;
  }

  /**
   * Validates that the request carries the current form password.
   *
   * <p>The password is read from either a standard parameter or a multipart field named {@code
   * "formPassword"} and then compared with {@link NodeClientCore#getFormPassword()}. The check is
   * intended for requests that mutate server state such as writes or configuration updates;
   * read-only requests typically do not require this validation.
   *
   * <p>To create forms that already embed the password, use {@link
   * PluginRespirator#addFormChild(HTMLNode, String, String)}. This method does not mutate the
   * request and has no side effects.
   *
   * @param req request whose parameters or parts may contain the form password; may be a multipart
   *     request
   * @return {@code true} when a password is present and matches the current node form password
   */
  @SuppressWarnings("unused")
  protected boolean isFormPassword(HTTPRequest req) {
    String passwd = req.getParam("formPassword", null);
    if (passwd == null) passwd = req.getPartAsStringFailsafe("formPassword", 32);
    return (passwd != null) && passwd.equals(pluginContext.clientCore.getFormPassword());
  }

  /**
   * Builds an error infobox containing the provided messages.
   *
   * <p>This convenience overload creates a standard error infobox without a retry link. Each error
   * string is rendered as a text node followed by a {@code <br>} for visual separation. The list is
   * not modified, and any ordering supplied by the caller is preserved.
   *
   * @param errors ordered, user-visible error messages to include in the infobox; entries should be
   *     non-null and already localized
   * @return the outer HTML node representing the error infobox container
   */
  @SuppressWarnings("unused")
  public HTMLNode createErrorBox(List<String> errors) {
    return createErrorBox(errors, null, null, null);
  }

  /**
   * Builds an error infobox with optional retry link parameters.
   *
   * <p>Each error message is rendered as a text node followed by a line break. When a retry URI is
   * provided, the method appends a link with the supplied path and a {@code key} parameter derived
   * from the retry URI. The {@code extraParams} string is concatenated directly to the retry URI
   * string, so callers are responsible for any separators or encoding they require.
   *
   * @param errors ordered, user-visible error messages to include in the infobox; entries should be
   *     non-null and already localized
   * @param path base path used for the retry link href; should be non-null when retry is enabled
   * @param retryUri URI to serialize as the retry {@code key} parameter; {@code null} disables the
   *     retry link
   * @param extraParams optional string appended to the retry URI serialization; may be {@code null}
   *     when no extra parameters are needed
   * @return the outer HTML node representing the error infobox container
   */
  public HTMLNode createErrorBox(
      List<String> errors, String path, FreenetURI retryUri, String extraParams) {
    InfoboxNode box = pluginContext.pageMaker.getInfobox("infobox-alert", "ERROR");
    HTMLNode errorBox = box.getContentNode();
    for (String error : errors) {
      errorBox.addChild("#", error);
      errorBox.addChild("br");
    }
    if (retryUri != null) {
      errorBox.addChild("#", "Retry: ");
      errorBox.addChild(
          new HTMLNode(
              "a",
              "href",
              path + "?key=" + ((extraParams == null) ? retryUri : (retryUri + extraParams)),
              retryUri.toString(false, false)));
    }
    return box.getOuterNode();
  }
}
