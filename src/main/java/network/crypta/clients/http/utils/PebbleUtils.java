package network.crypta.clients.http.utils;

import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.loader.ClasspathLoader;
import io.pebbletemplates.pebble.loader.Loader;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Map;
import network.crypta.clients.http.utils.L10nExtension.L10nFunction;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;

/**
 * Renders Pebble templates into {@link HTMLNode} trees for the HTTP UI.
 *
 * <p>This is a small, static helper that centralizes Pebble setup (template loader, suffix/prefix,
 * and the localization extension) so callers do not need to repeatedly construct a {@link
 * PebbleEngine}. Typical usage is to keep a model {@link Map} for one response, call {@link
 * #addChild(HTMLNode, String, Map, String)} for one or more fragments, and let the template engine
 * merge the model into HTML.
 *
 * <p>The utility is intentionally state-free from the caller's perspective. Internally it uses a
 * single shared {@link PebbleEngine} instance initialized with a {@link ClasspathLoader} rooted at
 * {@code network/crypta/clients/http/templates/} and {@code .html} suffixing. The engine is also
 * configured with {@link L10nExtension} using {@link NodeL10n#getBase()} by default, allowing
 * templates to resolve localized strings through the registered function.
 *
 * <ul>
 *   <li><b>Responsibility:</b> Render a named template with a model and attach the result to a
 *       parent {@link HTMLNode}.
 *   <li><b>Side effects:</b> Mutates the provided model by setting {@code l10nPrefix}.
 *   <li><b>Thread safety:</b> No synchronization is performed; callers should avoid concurrently
 *       mutating the same {@code model} or {@code parent} across threads.
 * </ul>
 *
 * @see L10nExtension
 * @see NodeL10n
 */
public class PebbleUtils {
  private static final String TEMPLATE_ROOT_PATH = "network/crypta/clients/http/templates/";
  private static final String TEMPLATE_NAME_SUFFIX = ".html";
  private static final PebbleEngine templateEngine;

  /**
   * Prevents instantiation of this utility class.
   *
   * <p>This type is a static utility holder and should not be instantiated. If construction is
   * attempted (for example via reflection), this constructor fails fast.
   */
  private PebbleUtils() {
    throw new UnsupportedOperationException("Utility class");
  }

  static {
    Loader<String> loader = new ClasspathLoader(PebbleUtils.class.getClassLoader());
    loader.setPrefix(PebbleUtils.TEMPLATE_ROOT_PATH);
    loader.setSuffix(PebbleUtils.TEMPLATE_NAME_SUFFIX);

    templateEngine =
        new PebbleEngine.Builder()
            .loader(loader)
            .extension(new L10nExtension(NodeL10n.getBase()))
            .build();
  }

  /**
   * Renders a classpath template and appends the evaluated output to a parent node.
   *
   * <p>This method loads {@code templateName} via the shared {@link PebbleEngine}, evaluates it
   * with the provided {@code model}, and appends the resulting text by calling {@link
   * HTMLNode#addChild(String, String)} with the {@code "%"} child tag. The model is mutated by
   * inserting a {@code l10nPrefix} key so templates can access a common localization prefix
   * consistently across pages.
   *
   * <p>Callers are expected to provide a per-request {@code model} and a {@code parent} that is
   * safe to mutate for the duration of rendering. This method does not perform validation beyond
   * what Pebble enforces, and it does not attempt to recover from template parse or evaluation
   * failures.
   *
   * <pre>{@code
   * HTMLNode parent = ...;
   * Map<String, Object> model = new java.util.HashMap<>();
   * PebbleUtils.addChild(parent, "status", model, "status.");
   * }</pre>
   *
   * @param parent The {@link HTMLNode} that receives the rendered output as a new child node.
   * @param templateName The template name resolved by the configured loader (without path prefix).
   * @param model Mutable model values used during evaluation; updated with {@code l10nPrefix}.
   * @param l10nPrefix Localization prefix stored under {@code l10nPrefix} for template lookups.
   * @throws IOException If template evaluation writes fail or Pebble reports an I/O error.
   */
  public static void addChild(
      HTMLNode parent, String templateName, Map<String, Object> model, String l10nPrefix)
      throws IOException {
    model.put("l10nPrefix", l10nPrefix);
    PebbleTemplate template = templateEngine.getTemplate(templateName);

    Writer writer = new StringWriter();
    template.evaluate(writer, model);

    parent.addChild("%", writer.toString());
  }

  /**
   * Sets the {@link BaseL10n l10n provider} to use with the {@link L10nFunction}. If this method is
   * not called, {@link NodeL10n}'s {@link NodeL10n#getBase() l10n provider} is used.
   *
   * <p>This method should only be called from tests.
   *
   * @param l10n The l10n provider to register for subsequent template evaluations
   */
  static void setBaseL10n(BaseL10n l10n) {
    // This removes the old function from the registry because the registry is a Map keyed by
    // function name.
    templateEngine.getExtensionRegistry().addExtension(new L10nExtension(l10n));
  }
}
