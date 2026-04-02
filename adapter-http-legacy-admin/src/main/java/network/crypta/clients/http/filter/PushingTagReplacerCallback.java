package network.crypta.clients.http.filter;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Map;
import network.crypta.client.filter.CommentException;
import network.crypta.client.filter.HTMLFilter.ParsedTag;
import network.crypta.client.filter.TagReplacerCallback;
import network.crypta.client.filter.URIProcessor;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.updateableelements.ImageElement;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.http.StaticResourcePaths;

/**
 * Tag replacer that injects client-side pushing support and rewrites image tags.
 *
 * <p>This callback is used by the HTML filtering pipeline to augment fetched pages with
 * FProxy-specific behaviors when web pushing is enabled. It is intentionally HTTP-specific and now
 * lives alongside the FProxy code that owns the surrounding request context, fetch tracker, and
 * static-resource paths.
 *
 * <p>The callback has two main responsibilities:
 *
 * <ul>
 *   <li>Replace eligible {@code <img>} elements with updateable image placeholders backed by the
 *       fetch tracker.
 *   <li>Inject the JavaScript, localization data, and hidden request identifier that the web
 *       pushing client expects in the final page.
 * </ul>
 *
 * <p>Instances are request-scoped. They hold references to the current {@link ToadletContext},
 * tracker, and size limit but do not retain any independent mutable state.
 */
public class PushingTagReplacerCallback implements TagReplacerCallback {

  private final FProxyFetchTracker tracker;
  private final long maxSize;
  private final ToadletContext ctx;

  /**
   * Creates a tag replacer for one filtered FProxy response.
   *
   * <p>The supplied tracker and request context are reused while the HTML filter walks the parsed
   * document. The maximum size is forwarded to updateable image elements so they apply the same
   * fetch limit as the surrounding request.
   *
   * @param tracker Fetch tracker that owns updateable elements for the current request.
   * @param maxSize Maximum fetch size, in bytes, for rewritten updateable elements.
   * @param ctx Active toadlet context used to inspect feature flags and request metadata.
   */
  public PushingTagReplacerCallback(FProxyFetchTracker tracker, long maxSize, ToadletContext ctx) {
    this.tracker = tracker;
    this.maxSize = maxSize;
    this.ctx = ctx;
  }

  /**
   * Builds the JavaScript localization object consumed by the web-pushing client.
   *
   * <p>The method exports every localization key under the {@code fproxy.push} prefix into a small
   * JavaScript object literal and HTML-encodes each translated value before embedding it into the
   * page. When no matching keys are present, the method still returns a syntactically valid empty
   * object.
   *
   * @return JavaScript source that initializes the client-side {@code l10n} object.
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
    return l10n.concat("\n};");
  }

  /**
   * Rewrites selected HTML tags for FProxy web-pushing support.
   *
   * <p>Only a small subset of tags is relevant here. Opening {@code <head>} tags receive the
   * client-side script and stylesheet references, closing {@code </body>} tags receive the hidden
   * request identifier and localization script, and eligible {@code <img>} tags are replaced with
   * updateable image placeholders. If web pushing is disabled or the tag does not require special
   * handling, the method returns {@code null} so the original sanitized tag remains in place.
   *
   * @param pt Sanitized parsed tag currently being emitted by the HTML filter.
   * @param uriProcessor URI helper used to sanitize and absolutize image sources.
   * @return Replacement markup for the tag, or {@code null} when no replacement is required.
   */
  @Override
  public String processTag(ParsedTag pt, URIProcessor uriProcessor) {
    if (!isPushingEnabled()) {
      return null;
    }

    String element = pt.element != null ? pt.element.toLowerCase(Locale.ROOT) : null;
    if ("img".equals(element)) {
      return handleImgTag(pt, uriProcessor);
    }
    if ("body".equals(element) && pt.isStartSlash()) {
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
            "<input id=\"requestId\" type=\"hidden\" value=\""
                + ctx.getUniqueId()
                + "\" name=\"requestId\"/>")
        .concat(
            "<script type=\"text/javascript\" language=\"javascript\">"
                .concat(getClientSideLocalizationScript())
                .concat("</script>"))
        .concat("</body>");
  }

  private String generateHeadInjection() {
    return "<head><script type=\"text/javascript\" language=\"javascript\""
        + " src=\""
        + StaticResourcePaths.ROOT_URL
        + "freenetjs/freenetjs.nocache.js\"></script><noscript><style>"
        + " .jsonly {display:none;}</style></noscript><link href=\""
        + StaticResourcePaths.ROOT_URL
        + "reset.css\" rel=\"stylesheet\" type=\"text/css\" />";
  }
}
