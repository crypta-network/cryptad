package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Detached snapshot of one legacy queue-page render.
 *
 * <p>The snapshot carries the localized page title used by the HTTP shell and one detached HTML
 * template fragment for the page body. The template may contain a very small set of well-defined
 * placeholders for request-context-only values such as alert summaries or form-password inputs.
 *
 * <p>Callers typically create the outer page shell, inject any request-local fragments that are
 * intentionally kept out of the runtime SPI, and then write the finished response. The snapshot
 * itself remains a plain JDK record, so it can cross module boundaries without exposing daemon or
 * HTTP framework types.
 *
 * @param pageTitle localized page title for the outer shell
 * @param contentHtmlTemplate detached HTML template fragment for the queue page body
 */
public record QueuePageSnapshot(String pageTitle, String contentHtmlTemplate) {
  /**
   * Creates an immutable queue-page snapshot.
   *
   * <p>The constructor enforces that both record components are present because the HTTP layer
   * always needs a title and a body fragment to complete the response.
   *
   * @param pageTitle localized page title for the outer shell that wraps the detached queue body
   * @param contentHtmlTemplate detached HTML fragment, including any approved placeholder tokens
   * @throws NullPointerException if either argument is {@code null}
   */
  public QueuePageSnapshot {
    Objects.requireNonNull(pageTitle, "pageTitle");
    Objects.requireNonNull(contentHtmlTemplate, "contentHtmlTemplate");
  }
}
