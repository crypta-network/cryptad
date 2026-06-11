package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import network.crypta.runtime.spi.DiagnosticPort;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.support.api.HTTPRequest;

/**
 * Serves the `/diagnostic/` HTTP endpoint that renders the detached runtime diagnostic report.
 *
 * <p>This toadlet remains a legacy admin-facing plaintext endpoint, but it no longer traverses the
 * daemon directly. Instead, it requests one read-only report snapshot from {@link DiagnosticPort}
 * and serializes the returned sections in order, keeping {@code Node}, FCP, and thread/stat
 * implementation types out of the HTTP layer.
 */
public class DiagnosticToadlet extends Toadlet {
  private static final String PLAIN_TEXT_CONTENT_TYPE = "text/plain; charset=utf-8";
  private static final String FORBIDDEN_REASON = "Forbidden";

  /**
   * Relative path where this toadlet is mounted within the HTTP interface.
   *
   * <p>The value is shared with router configuration and should remain stable so bookmarked
   * diagnostic URLs and automated monitoring checks continue to resolve.
   */
  public static final String TOADLET_URL = "/diagnostic/";

  private final DiagnosticPort diagnostic;

  /**
   * Builds a diagnostic toadlet bound to the provided diagnostic port.
   *
   * @param diagnostic read-only runtime port that supplies detached diagnostic report snapshots
   */
  protected DiagnosticToadlet(DiagnosticPort diagnostic) {
    super();
    this.diagnostic = diagnostic;
  }

  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (!ctx.checkFullAccess(this)) {
      return;
    }

    writeTextReply(ctx, 200, "OK", render(diagnostic.snapshot()));
  }

  /**
   * Handles header-only diagnostic export probes.
   *
   * <p>The Wave 4 explicit legacy fallback marker allows safe-read methods. HEAD therefore follows
   * the same access checks and snapshot rendering path as GET to report the matching content
   * length, but intentionally suppresses the plaintext body. Access denial also stays header-only:
   * the ordinary {@link ToadletContext#checkFullAccess(Toadlet)} helper renders an HTML page for
   * GET, so this method performs the same boolean access check directly before sending a bodyless
   * 403 response.
   *
   * @param uri request URI, including any explicit fallback marker already accepted by the removal
   *     policy
   * @param request HTTP request wrapper
   * @param ctx request context used to write response headers
   * @throws ToadletContextClosedException if the client disconnects before headers are written
   * @throws IOException if the response headers cannot be written
   */
  @SuppressWarnings("unused")
  public void handleMethodHEAD(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!ctx.isAllowedFullAccess()) {
      ctx.sendReplyHeaders(403, FORBIDDEN_REASON, null, null, 0L, true);
      return;
    }

    byte[] body = render(diagnostic.snapshot()).getBytes(StandardCharsets.UTF_8);
    ctx.sendReplyHeaders(200, "OK", null, PLAIN_TEXT_CONTENT_TYPE, body.length, true);
  }

  @Override
  public String path() {
    return TOADLET_URL;
  }

  private String render(DiagnosticReportSnapshot snapshot) {
    StringBuilder builder = new StringBuilder();
    LegacyAdminRetirementRegistry.findById("diagnostic")
        .flatMap(LegacyAdminRetirementNotice::renderPlainText)
        .ifPresent(builder::append);
    for (DiagnosticSectionSnapshot section : snapshot.sections()) {
      builder.append(section.title()).append('\n');
      for (String line : section.lines()) {
        builder.append(line).append('\n');
      }
    }
    return builder.toString();
  }
}
