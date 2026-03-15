package network.crypta.runtime.spi;

import java.util.List;
import java.util.Objects;

/**
 * One line-oriented section of the detached diagnostic report.
 *
 * <p>The {@code title} is the exact section header line the caller should write before the section
 * body. The {@code lines} list contains each following line in order and may include empty strings
 * when the legacy report expects blank separator lines between sections. Consumers should treat the
 * section as presentation-ready text rather than as a semantic metrics container.
 *
 * <p>This deliberately simple shape matches the current diagnostic page: one heading followed by a
 * sequence of preformatted lines. That keeps formatting decisions in the daemon adapter and avoids
 * leaking daemon-only helper types or introducing a broad schema for a page that is expected to
 * remain a legacy administrative report.
 *
 * @param title section header line to render
 * @param lines ordered body lines for the section, including any intentional blank lines
 */
public record DiagnosticSectionSnapshot(String title, List<String> lines) {
  /**
   * Creates an immutable diagnostic section snapshot.
   *
   * <p>The constructor requires a non-null title and defensively copies the line list, so the
   * snapshot remains detached from later caller mutations. The caller is responsible for supplying
   * lines in the exact order they should appear in output, including any intentional blank lines
   * used to preserve the legacy plaintext layout.
   *
   * @param title section header line to expose through {@link #title()}
   * @param lines ordered section body lines to expose through {@link #lines()}
   * @throws NullPointerException if {@code title} or {@code lines} is {@code null}
   */
  public DiagnosticSectionSnapshot {
    Objects.requireNonNull(title, "title");
    Objects.requireNonNull(lines, "lines");
    lines = List.copyOf(lines);
  }
}
