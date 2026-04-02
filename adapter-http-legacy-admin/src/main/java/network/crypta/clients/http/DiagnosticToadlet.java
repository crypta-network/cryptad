package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
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

  /**
   * Relative path where this toadlet is mounted within the HTTP interface.
   *
   * <p>The value is shared with router configuration and should remain stable so bookmarked
   * diagnostic URLs and automated monitoring checks continue to resolve.
   */
  public static final String TOADLET_URL = "/diagnostic/";

  private final DiagnosticPort diagnostic;

  /**
   * Builds a diagnostic toadlet bound to the provided client plumbing and diagnostic port.
   *
   * @param client HTTP client facade supplied to the superclass for response handling
   * @param diagnostic read-only runtime port that supplies detached diagnostic report snapshots
   */
  protected DiagnosticToadlet(HighLevelSimpleClient client, DiagnosticPort diagnostic) {
    super(client);
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

  @Override
  public String path() {
    return TOADLET_URL;
  }

  private String render(DiagnosticReportSnapshot snapshot) {
    StringBuilder builder = new StringBuilder();
    for (DiagnosticSectionSnapshot section : snapshot.sections()) {
      builder.append(section.title()).append('\n');
      for (String line : section.lines()) {
        builder.append(line).append('\n');
      }
    }
    return builder.toString();
  }
}
