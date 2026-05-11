package network.crypta.clients.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.MultiValueTable;

/**
 * Emits small replacement responses for removed-by-default legacy admin pages.
 *
 * <p>The body is intentionally static apart from registry title and same-origin replacement link.
 * It avoids echoing the incoming request URI, query string, form data, uploaded filenames, peer
 * references, Freenet/Crypta URIs, cookies, tokens, or remote addresses.
 *
 * <p>The dispatcher calls this writer only after {@link LegacyAdminRemovalPolicy} has produced a
 * concrete {@link LegacyAdminRemovalDecision}. It is responsible for converting that decision into
 * HTTP headers and, for non-{@code HEAD} requests, a compact HTML body. It does not perform route
 * matching, replacement-availability checks, or diagnostics recording. Keeping those steps outside
 * the writer makes the response path easy to audit: every dynamic value comes from the bounded
 * registry metadata already validated by {@link LegacyAdminSurface}.
 *
 * <p>Responses are deliberately plain. Operators get one explanation sentence and one replacement
 * link; automated clients get stable status codes and an optional {@code Location} header.
 */
final class LegacyAdminReplacementResponse {
  /** MIME type used for the small replacement explanation page. */
  private static final String MIME_TYPE = "text/html; charset=UTF-8";

  /** Prevents construction because response writing is a stateless helper operation. */
  private LegacyAdminReplacementResponse() {}

  /**
   * Sends the HTTP response described by a removal decision.
   *
   * <p>Redirect decisions receive a {@code Location} header that points to the same-origin
   * replacement URL. Gone and blocked-mutation decisions omit that header but still use the body to
   * expose the replacement link to human operators. For {@code HEAD}, the method sends the same
   * headers and content length that a {@code GET} would receive, then suppresses the body.
   *
   * @param decision validated removal decision produced by the central policy
   * @param method uppercase HTTP method from the request line
   * @param ctx request context used to write headers and optional response bytes
   * @throws ToadletContextClosedException if the client connection closes while writing
   * @throws IOException if the response stream fails while headers or body bytes are written
   */
  static void send(LegacyAdminRemovalDecision decision, String method, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    byte[] body = body(decision).getBytes(StandardCharsets.UTF_8);
    MultiValueTable<String, String> headers =
        decision.redirect() ? MultiValueTable.from("Location", decision.replacementUrl()) : null;
    ctx.sendReplyHeaders(
        decision.statusCode(), decision.reason(), headers, MIME_TYPE, body.length, true);
    if (!"HEAD".equals(method)) {
      ctx.writeData(body);
    }
  }

  /**
   * Builds the small safe HTML body for a replacement response.
   *
   * <p>The generated markup uses only registry title, replacement label, and replacement URL. Each
   * value is HTML-encoded even though registry construction already restricts replacement URLs to
   * same-origin absolute paths. The extra encoding keeps this method safe if future registry text
   * contains punctuation or localized labels.
   *
   * @param decision validated removal decision that supplies the surface and replacement URL
   * @return complete UTF-8 HTML document body for non-{@code HEAD} responses
   */
  private static String body(LegacyAdminRemovalDecision decision) {
    LegacyAdminSurface surface = decision.surface();
    String title =
        decision.usageEvent() == LegacyAdminUsageEvent.BLOCKED_MUTATING_REQUEST
            ? "Legacy action disabled"
            : "Legacy page replaced";
    String lead =
        decision.usageEvent() == LegacyAdminUsageEvent.BLOCKED_MUTATING_REQUEST
            ? "This legacy admin action is no longer executed by default."
            : "This legacy admin page no longer renders by default.";
    String replacementLabel =
        surface.replacementLabel() == null ? surface.replacementUrl() : surface.replacementLabel();
    return "<!doctype html><html><head><meta charset=\"utf-8\"><title>"
        + HTMLEncoder.encode(title)
        + "</title></head><body><h1>"
        + HTMLEncoder.encode(title)
        + "</h1><p>"
        + HTMLEncoder.encode(lead)
        + "</p><p>Use <a href=\""
        + HTMLEncoder.encode(decision.replacementUrl())
        + "\">"
        + HTMLEncoder.encode(replacementLabel)
        + "</a> for "
        + HTMLEncoder.encode(surface.title())
        + ".</p></body></html>";
  }
}
