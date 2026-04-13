package network.crypta.clients.http;

import java.io.IOException;
import java.util.Map;
import network.crypta.clients.http.utils.PebbleUtils;
import network.crypta.support.HTMLNode;

/**
 * Base toadlet that embeds Pebble template fragments into an existing {@link HTMLNode} tree.
 *
 * <p>Subclasses use this helper when they need to stitch localized template output into pages that
 * are already being composed in memory rather than streamed directly to the client. It keeps the
 * templating concerns narrowly focused on delegating to {@link PebbleUtils}, while leaving request
 * routing, validation, and error handling to concrete toadlets. The class is stateless apart from
 * the shared HTTP shell, so instances can be reused across requests as long as callers supply
 * thread-safe model data and do not share mutable {@link HTMLNode} trees unsafely.
 *
 * <p>Typical usage is to build an {@code HTMLNode} hierarchy with structural elements, then call
 * {@link #addChild(HTMLNode, String, Map, String)} for each section that should be rendered from a
 * Pebble template with optional localization prefixes.
 *
 * <ul>
 *   <li>Encapsulates the Pebble rendering call for partial templates.
 *   <li>Supports per-call localization namespaces through {@code l10nPrefix}.
 *   <li>Leaves ownership of the provided nodes and model maps with the caller.
 * </ul>
 *
 * @see PebbleUtils
 * @see HTMLNode
 */
abstract class WebTemplateToadlet extends Toadlet {

  /** Creates a template-aware toadlet wrapper. */
  WebTemplateToadlet() {
    super();
  }

  /**
   * Renders the specified Pebble template and appends its HTML output to the given parent node.
   *
   * <p>The method resolves the template by name (without extension), renders it with the supplied
   * model map, and attaches the resulting markup as a child of {@code parent}. When {@code
   * l10nPrefix} is non-empty, it is forwarded to the underlying renderer so message lookups are
   * scoped to that prefix; callers commonly pass an empty string to use the default namespace. The
   * operation is deterministic for the same model input and does not mutate the model map. The
   * caller retains ownership of {@code parent}; the method modifies the node in place.
   *
   * <pre>{@code
   * HTMLNode container = new HTMLNode("div");
   * addChild(container, "status-panel", Map.of("status", "ok"), "ui.status.");
   * }</pre>
   *
   * @param parent parent HTML node that receives the rendered template output; must not be {@code
   *     null} and should be mutable.
   * @param templateName logical template identifier without file extension; must match a template
   *     available to {@link PebbleUtils}.
   * @param model variables exposed to the template during rendering; values are read-only for the
   *     duration of the call.
   * @param l10nPrefix prefix prepended to localization keys during template rendering; use an empty
   *     string to disable prefixing.
   * @throws IOException if the template cannot be read or rendered due to underlying I/O issues.
   */
  @SuppressWarnings("SameParameterValue")
  void addChild(HTMLNode parent, String templateName, Map<String, Object> model, String l10nPrefix)
      throws IOException {
    PebbleUtils.addChild(parent, templateName, model, l10nPrefix);
  }
}
