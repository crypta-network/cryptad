package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Detached snapshot of the current connection-type notice shown on the connectivity page.
 *
 * <p>The legacy connectivity page can surface more than a plain string. Depending on the detected
 * NAT or UDP state, the page may need to preserve the full alert infobox, including severity
 * styling, operator guidance links, and dismiss controls. This record therefore carries both a
 * localized plain-text representation and an optional pre-rendered HTML fragment that keeps the old
 * behavior when the HTTP layer is no longer coupled to daemon alert classes.
 *
 * <p>The rendered fragment may be blank when the adapter cannot produce alert HTML. Callers should
 * then fall back to the plain title and body fields.
 *
 * @param title localized notice title suitable for fallback rendering or tests
 * @param text localized plain-text notice body suitable for fallback rendering or tests
 * @param renderedAlertHtml rendered alert HTML preserving the legacy infobox, help link, and
 *     dismiss UI, or an empty string when plain-text fallback should be used
 */
public record ConnectivityNoticeSnapshot(String title, String text, String renderedAlertHtml) {
  /**
   * Creates an immutable notice snapshot.
   *
   * <p>All components are required. Callers that do not have rendered alert markup available should
   * pass an empty string rather than {@code null}.
   *
   * @throws NullPointerException if any component is {@code null}
   */
  public ConnectivityNoticeSnapshot {
    Objects.requireNonNull(title, "title");
    Objects.requireNonNull(text, "text");
    Objects.requireNonNull(renderedAlertHtml, "renderedAlertHtml");
  }
}
