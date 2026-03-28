package network.crypta.runtime.admin.queue.page;

import java.util.Objects;

/**
 * Bundles the non-counter flags required to render a queue progress cell.
 *
 * <p>The queue page derives block counters separately from request status objects, but the progress
 * renderer also needs a few boolean and enum flags to decide whether it should show a progress bar
 * at all. This record groups those non-counter inputs into one immutable value so callers can pass
 * a stable rendering context without keeping HTTP-layer helper types alive.
 *
 * <p>Instances are safe to reuse within one render pass because the record is immutable. The
 * compact constructor enforces a non-null compression state, so rendering code can branch on the
 * enum directly instead of carrying nullable checks through every call path.
 *
 * @param advancedMode {@code true} to render detailed progress fractions when available
 * @param started {@code true} once the request has moved beyond its initial waiting state
 * @param compressing current compression state used to select early progress messaging
 * @param upload {@code true} when rendering an upload progress cell instead of a download cell
 */
public record QueueProgressCellContext(
    boolean advancedMode, boolean started, QueueCompressionState compressing, boolean upload) {
  /**
   * Creates a progress-cell rendering context with a stable non-counter state.
   *
   * @throws NullPointerException if {@code compressing} is {@code null}
   */
  public QueueProgressCellContext {
    Objects.requireNonNull(compressing, "compressing");
  }
}
