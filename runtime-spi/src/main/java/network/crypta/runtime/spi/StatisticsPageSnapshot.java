package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Detached snapshot of the legacy statistics page content.
 *
 * <p>This record carries the already-rendered HTML template fragment for one statistics-page
 * response together with the small amount of detached page state that the HTTP layer still needs to
 * inject request-context-only controls. The template may contain well-defined placeholders for
 * items such as alert summaries or form-password-protected controls that must be rendered with a
 * live {@code ToadletContext}.
 *
 * <p>The snapshot is immutable after construction. The HTML template is represented as a plain
 * {@link String} rather than as daemon-specific DOM types so the runtime SPI remains JDK-only and
 * detached from the legacy HTTP rendering classes.
 *
 * @param contentHtmlTemplate detached HTML template fragment for the statistics page body
 * @param wrapperEnabled whether the daemon can show the thread-dump form control
 * @param latestLogsEnabled whether the daemon can show the latest-log link
 */
public record StatisticsPageSnapshot(
    String contentHtmlTemplate, boolean wrapperEnabled, boolean latestLogsEnabled) {
  /**
   * Creates an immutable statistics-page snapshot.
   *
   * @param contentHtmlTemplate detached HTML body template for one legacy statistics render
   * @param wrapperEnabled whether the runtime currently supports the wrapper-backed thread dump
   * @param latestLogsEnabled whether the latest-log link should be shown
   * @throws NullPointerException if {@code contentHtmlTemplate} is {@code null}
   */
  public StatisticsPageSnapshot {
    Objects.requireNonNull(contentHtmlTemplate, "contentHtmlTemplate");
  }
}
