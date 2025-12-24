package network.crypta.client.filter;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Map;
import network.crypta.client.filter.HTMLFilter.ParsedTag;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.updateableelements.ImageElement;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLEncoder;

/**
 * Tag replacer that injects client‑side pushing support and rewrites image tags.
 *
 * <p>This callback is used by the HTML filtering pipeline to augment fetched pages with
 * FProxy-specific behaviors when web pushing is enabled. It performs two main tasks:
 *
 * <ul>
 *   <li>Rewrites {@code <img>} elements to client-side updatable placeholders backed by {@link
 *       network.crypta.clients.http.updateableelements.ImageElement}, enabling progressive fetching
 *       and display while honoring size limits.
 *   <li>Injects required script and localization snippets into the document {@code <head>} and
 *       before the closing {@code </body>} to initialize the push runtime and UI strings.
 * </ul>
 *
 * <p>Instances are immutable after construction and hold references to the tracker, the maximum
 * response size, and the current {@link network.crypta.clients.http.ToadletContext}. They do not
 * maintain additional internal state. Concurrency: the class is safe for concurrent use provided
 * that the supplied tracker and context are themselves safe to use from the calling threads. The
 * callback returns {@code null} for tags it does not handle, allowing the caller to leave the
 * original content unchanged.
 *
 * <p>Typical usage is to construct the callback once per request and pass it to the surrounding
 * HTML filter, which calls {@link #processTag(HTMLFilter.ParsedTag, URIProcessor)} for each parsed
 * token. The behavior is a no-op unless both JavaScript and web pushing are enabled in the
 * container.
 *
 * @see TagReplacerCallback
 * @see HTMLFilter
 * @see network.crypta.clients.http.updateableelements.ImageElement
 * @see network.crypta.clients.http.FProxyFetchTracker
 * @see network.crypta.clients.http.ToadletContext
 */
public class PushingTagReplacerCallback implements TagReplacerCallback {

  /** The FProxyFetchTracker */
  private final FProxyFetchTracker tracker;

  /** The maxSize used for fetching */
  private final long maxSize;

  /** The current ToadletContext */
  private final ToadletContext ctx;

  /**
   * Creates a new callback configured for the current request lifecycle.
   *
   * <p>The instance holds the provided tracker, size limit, and context for later use while
   * processing HTML tags. It does not start any network operations by itself; work happens lazily
   * when {@link #processTag(HTMLFilter.ParsedTag, URIProcessor)} is invoked by the filter.
   *
   * @param tracker The fetch tracker used to account, correlate, and observe pushed sub‑requests;
   *     must be the tracker associated with the enclosing page request.
   * @param maxSize Maximum number of bytes permitted for rewritten image fetches; values at or
   *     below zero are treated as non-positive limits by downstream components.
   * @param ctx The active {@link ToadletContext} providing configuration and unique request id;
   *     must not be {@code null} for push injection to be effective.
   */
  public PushingTagReplacerCallback(FProxyFetchTracker tracker, long maxSize, ToadletContext ctx) {
    this.tracker = tracker;
    this.maxSize = maxSize;
    this.ctx = ctx;
  }

  /**
   * Builds the JavaScript snippet that initializes client‑side localization keys.
   *
   * <p>The generated code defines a global {@code l10n} object containing key/value pairs derived
   * from the node’s translation bundle under the {@code fproxy.push.*} prefix. The snippet is
   * intended to be injected into the document so subsequent scripts can reference translated UI
   * strings without additional network round‑trips. Keys are HTML‑encoded for safety, and the
   * builder elides the trailing comma when no entries are present.
   *
   * @return A non‑{@code null} JavaScript string that declares {@code var l10n = {...};}; empty
   *     objects are possible when no matching translation keys exist.
   */
  public static String getClientSideLocalizationScript() {
    StringBuilder l10nBuilder = new StringBuilder("var l10n={\n");
    boolean isNamePresentAtLeastOnce = false;
    for (String key : NodeL10n.getBase().getAllNamesWithPrefix("fproxy.push")) {
      l10nBuilder
          .append(key.substring("fproxy.push".length() + 1))
          .append(": \"")
          .append(HTMLEncoder.encode(NodeL10n.getBase().getString(key)))
          .append("\",\n");
      isNamePresentAtLeastOnce = true;
    }
    String l10n =
        isNamePresentAtLeastOnce
            ? l10nBuilder.substring(0, l10nBuilder.length() - 2)
            : l10nBuilder.toString();
    l10n = l10n.concat("\n};");
    return l10n;
  }

  /**
   * Processes a single parsed tag and returns an optional replacement fragment.
   *
   * <p>When pushing is enabled, the method:
   *
   * <ul>
   *   <li>Rewrites {@code <img>} elements to an updatable client‑side representation tied to the
   *       current request and {@link #maxSize}.
   *   <li>Injects the push/runtime script into an opening {@code <head>} tag.
   *   <li>Appends localization and a hidden {@code requestId} input before the closing {@code
   *       </body>} tag.
   * </ul>
   *
   * For all other tags or when pushing is disabled, the method returns {@code null} to indicate no
   * change.
   *
   * <p>Idempotency: the method computes output solely from the supplied tag, the request context,
   * and current configuration, and does not mutate the instance. Invalid or malformed tags are
   * safely ignored.
   *
   * <pre>{@code
   * // Example: use inside an HTML filter loop
   * var cb = new PushingTagReplacerCallback(tracker, maxSize, ctx);
   * var replacement = cb.processTag(pt, uriProcessor);
   * }</pre>
   *
   * @param pt The parsed tag including name, attributes, and position; passes through unchanged
   *     when the element is not handled or pushing is disabled.
   * @param uriProcessor Helper used to normalize and absolutize {@code src} attributes; must be
   *     capable of resolving relative paths in the page’s base context.
   * @return Either a replacement HTML fragment to splice into the output, or {@code null} to leave
   *     the original tag untouched by this callback.
   */
  @Override
  public String processTag(ParsedTag pt, URIProcessor uriProcessor) {
    if (!isPushingEnabled()) {
      return null;
    }

    // pt.element can be null for malformed or empty tokens; guard to avoid NPE
    String element = pt.element != null ? pt.element.toLowerCase(Locale.ROOT) : null;
    if ("img".equals(element)) {
      return handleImgTag(pt, uriProcessor);
    }
    if ("body".equals(element) && pt.startSlash) {
      return generateBodyCloseInjection();
    }
    if ("head".equals(element)) {
      return generateHeadInjection();
    }
    return null;
  }

  private boolean isPushingEnabled() {
    return ctx.getContainer().isFProxyJavascriptEnabled()
        && ctx.getContainer().isFProxyWebPushingEnabled();
  }

  private String handleImgTag(ParsedTag pt, URIProcessor uriProcessor) {
    Map<String, String> attrs = pt.getAttributesAsMap();
    String value = attrs.get("src");
    if (value == null) {
      return null;
    }
    String src;
    try {
      src = uriProcessor.makeURIAbsolute(uriProcessor.processURI(value, null, false, false));
    } catch (CommentException | URISyntaxException _) {
      return null;
    }
    if (src.startsWith("/")) {
      src = src.substring(1);
    }
    try {
      return new ImageElement(tracker, new FreenetURI(src), maxSize, ctx, pt, true).generate();
    } catch (MalformedURLException _) {
      return null;
    }
  }

  private String generateBodyCloseInjection() {
    return ""
        .concat(
            /*new XmlAlertElement(ctx).generate()*/ ""
                .concat(
                    "<input id=\"requestId\" type=\"hidden\" value=\""
                        + ctx.getUniqueId()
                        + "\" name=\"requestId\"/>"))
        .concat(
            "<script type=\"text/javascript\" language=\"javascript\">"
                .concat(getClientSideLocalizationScript())
                .concat("</script>"))
        .concat("</body>");
  }

  private String generateHeadInjection() {
    return "<head><script type=\"text/javascript\" language=\"javascript\""
        + " src=\"/static/freenetjs/freenetjs.nocache.js\"></script><noscript><style>"
        + " .jsonly {display:none;}</style></noscript><link href=\"/static/reset.css\""
        + " rel=\"stylesheet\" type=\"text/css\" />";
  }
}
