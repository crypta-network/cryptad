package network.crypta.clients.http;

import java.util.Optional;
import network.crypta.support.HTMLNode;

/**
 * Renders reusable fallback notices for replaced legacy admin pages.
 *
 * <p>The notice is intentionally non-blocking. It explains that the legacy page still exists for
 * fallback and debug use, then links to the Web Shell or first-party app route that should be the
 * primary operator path. Page builders can call this helper once near the top of a legacy page
 * instead of embedding per-toadlet warning HTML, which keeps the wording, CSS classes, and fallback
 * semantics aligned with {@link LegacyAdminRetirementRegistry}.
 *
 * <p>The helper is stateless and thread-safe. It does not decide whether a route is replaced; it
 * trusts the supplied {@link LegacyAdminSurface}. HTML rendering uses existing {@link HTMLNode}
 * primitives and same-origin URLs already validated by the surface model. Plain-text rendering uses
 * fixed line-feed separators because legacy diagnostic exports are byte-for-byte HTTP payloads and
 * should not vary by host operating system.
 *
 * <ul>
 *   <li>HTML pages use {@link #render(LegacyAdminSurface)} or {@link #addTo(HTMLNode,
 *       LegacyAdminSurface)}.
 *   <li>Plain-text exports use {@link #renderPlainText(LegacyAdminSurface)}.
 *   <li>Pending, retained, and infrastructure surfaces return an empty result by design.
 * </ul>
 */
public final class LegacyAdminRetirementNotice {
  private static final String CSS_CLASS_ATTRIBUTE = "class";
  private static final String NOTICE_CLASS =
      "infobox infobox-information legacy-admin-retirement-notice";
  private static final String INFOBOX_HEADER_CLASS = "infobox-header";
  private static final String INFOBOX_CONTENT_CLASS = "infobox-content";
  private static final String NOTICE_HEADER = "Legacy fallback page";
  private static final String FALLBACK_TEXT =
      "This legacy page remains available as a fallback and debug view.";
  private static final String PRIMARY_FLOW_PREFIX = "The primary flow is now in ";
  private static final String PLAIN_TEXT_LINE_SEPARATOR = "\n";

  private LegacyAdminRetirementNotice() {}

  /**
   * Builds a notice node for a replaced surface.
   *
   * <p>The method returns an empty value for {@code null}, retained, pending, fallback, or
   * infrastructure surfaces. For replaced pages it creates a complete infobox node containing the
   * standard fallback sentence and one replacement link. Callers own the returned node and can
   * attach it to the page content tree without further mutation.
   *
   * @param surface registry metadata for the legacy surface being rendered; may be {@code null}
   * @return notice HTML when the surface is primary-replaced, otherwise an empty optional
   */
  public static Optional<HTMLNode> render(LegacyAdminSurface surface) {
    if (surface == null || !surface.rendersNotice()) {
      return Optional.empty();
    }

    HTMLNode notice = new HTMLNode("div", CSS_CLASS_ATTRIBUTE, NOTICE_CLASS);
    notice.addChild("div", CSS_CLASS_ATTRIBUTE, INFOBOX_HEADER_CLASS, NOTICE_HEADER);
    HTMLNode content = notice.addChild("div", CSS_CLASS_ATTRIBUTE, INFOBOX_CONTENT_CLASS);
    content.addChild("p", FALLBACK_TEXT);
    HTMLNode primaryFlow = content.addChild("p");
    primaryFlow.addChild("#", PRIMARY_FLOW_PREFIX);
    primaryFlow.addChild("a", "href", surface.replacementUrl(), replacementLabel(surface));
    primaryFlow.addChild("#", ".");
    return Optional.of(notice);
  }

  /**
   * Appends a notice for a replaced surface to an existing page content node.
   *
   * <p>This convenience method is suitable for shared page builders such as {@link PageMaker}. It
   * leaves {@code parent} unchanged when the surface does not render a notice, so callers do not
   * need to duplicate the retirement-state checks. The parent node must be the page content area
   * where an infobox is valid.
   *
   * @param parent destination node that receives the generated notice when one exists
   * @param surface registry metadata for the current legacy route; may be {@code null}
   */
  public static void addTo(HTMLNode parent, LegacyAdminSurface surface) {
    render(surface).ifPresent(parent::addChild);
  }

  /**
   * Builds a plain-text notice for non-HTML legacy exports.
   *
   * <p>The returned text mirrors the HTML notice wording and ends with a blank line so the caller
   * can prepend it directly to an existing report. The format deliberately uses {@code \n} instead
   * of {@link System#lineSeparator()} to keep HTTP diagnostic exports stable across Linux, macOS,
   * and Windows hosts.
   *
   * @param surface registry metadata for the non-HTML legacy export; may be {@code null}
   * @return plain-text notice when the surface is primary-replaced, otherwise an empty optional
   */
  public static Optional<String> renderPlainText(LegacyAdminSurface surface) {
    if (surface == null || !surface.rendersNotice()) {
      return Optional.empty();
    }
    return Optional.of(
        NOTICE_HEADER
            + PLAIN_TEXT_LINE_SEPARATOR
            + FALLBACK_TEXT
            + PLAIN_TEXT_LINE_SEPARATOR
            + PRIMARY_FLOW_PREFIX
            + replacementLabel(surface)
            + ": "
            + surface.replacementUrl()
            + PLAIN_TEXT_LINE_SEPARATOR
            + PLAIN_TEXT_LINE_SEPARATOR);
  }

  private static String replacementLabel(LegacyAdminSurface surface) {
    return surface.replacementLabel() == null
        ? surface.replacementUrl()
        : surface.replacementLabel();
  }
}
