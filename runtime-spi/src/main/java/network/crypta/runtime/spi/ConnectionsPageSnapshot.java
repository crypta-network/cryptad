package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Detached snapshot of one legacy connections-page render.
 *
 * <p>The snapshot carries the page title, peer count, whether the peer table must be wrapped in a
 * request-context form, and three detached HTML fragments. The outer HTTP layer still owns alert
 * injection, access checks, reply writing, and form-password handling, so the adapter returns the
 * peer-table fragment separately from the surrounding content. This keeps the SPI page-oriented and
 * practical without leaking {@code ToadletContext}, {@code HTMLNode}, or daemon peer types.
 *
 * @param pageTitle localized page title for the response shell
 * @param peerCount number of peers included in the rendered page snapshot
 * @param peerActionsEnabled whether the peer table content expects a request-context form wrapper
 * @param contentHtmlBeforePeerTable detached HTML fragment emitted before {@code peerTableHtml}
 * @param peerTableHtml detached peer-table fragment, or other peer-section body content
 * @param contentHtmlAfterPeerTable detached HTML fragment emitted after {@code peerTableHtml}
 */
public record ConnectionsPageSnapshot(
    String pageTitle,
    int peerCount,
    boolean peerActionsEnabled,
    String contentHtmlBeforePeerTable,
    String peerTableHtml,
    String contentHtmlAfterPeerTable) {
  /**
   * Creates an immutable connections-page snapshot.
   *
   * @throws NullPointerException if any HTML fragment or the page title is {@code null}
   */
  public ConnectionsPageSnapshot {
    Objects.requireNonNull(pageTitle, "pageTitle");
    Objects.requireNonNull(contentHtmlBeforePeerTable, "contentHtmlBeforePeerTable");
    Objects.requireNonNull(peerTableHtml, "peerTableHtml");
    Objects.requireNonNull(contentHtmlAfterPeerTable, "contentHtmlAfterPeerTable");
  }
}
