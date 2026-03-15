package network.crypta.runtime.spi;

import java.util.List;
import java.util.Objects;

/**
 * Detached snapshot of the legacy diagnostic report.
 *
 * <p>This record groups the ordered section snapshots that make up the plain-text diagnostic page.
 * Each section already contains the text lines needed for rendering, so higher layers can simply
 * iterate in order and write them without consulting the daemon state again. The record therefore
 * acts as a request-scoped transport object between the daemon-backed adapter and presentation
 * layers such as the legacy HTTP toadlet.
 *
 * <p>The snapshot is immutable after construction. Collection components are defensively copied,
 * which means callers can sort, cache, or hand the report off to another rendering step without
 * risking accidental mutation of the adapter-owned state. The section order is significant and
 * should be preserved by consumers that want to keep the traditional operator-facing report
 * structure.
 *
 * @param sections ordered diagnostic sections for the current report snapshot
 * @see DiagnosticSectionSnapshot
 */
public record DiagnosticReportSnapshot(List<DiagnosticSectionSnapshot> sections) {
  /**
   * Creates an immutable report snapshot.
   *
   * <p>The constructor defensively copies the section list so callers can retain the snapshot for
   * the duration of a request without observing later mutations to the source collection. The
   * supplied list must already be ordered exactly as the consumer should render it; this type does
   * not reorder, filter, or normalize the section sequence.
   *
   * @param sections ordered section list to copy into the immutable snapshot
   * @throws NullPointerException if {@code sections} is {@code null}
   */
  public DiagnosticReportSnapshot {
    Objects.requireNonNull(sections, "sections");
    sections = List.copyOf(sections);
  }
}
