package org.sevenzip;

/**
 * Callback interface that receives incremental progress updates from codecs and container
 * operations.
 *
 * <p>This hook is used by long-running compression or extraction tasks to surface how many bytes
 * have been consumed from the source stream and how many have been produced on the destination.
 * Implementations typically bridge these notifications to user interfaces, logging subsystems, or
 * cooperative cancellation checks so that callers can remain responsive while large archives are
 * processed. The interface is intentionally minimal to allow lightweight implementations; concrete
 * classes decide whether they are thread-safe, whether they smooth updates, or whether they trigger
 * downstream side effects such as UI refreshes.
 *
 * <p>Common responsibilities include:
 *
 * <ul>
 *   <li>Recording cumulative byte counts for progress bars or rate estimators.
 *   <li>Forwarding the update to observers that may stop work when thresholds are exceeded.
 *   <li>Emitting structured logs so long-running tasks can be monitored externally.
 * </ul>
 *
 * <p>Callers should document their update frequency and whether they guarantee monotonic counts so
 * that implementers can manage contention and avoid excessive overhead on tight inner loops.
 */
public interface ICodeProgress {

  /**
   * Reports the current cumulative byte counts for an ongoing coding operation.
   *
   * <p>Callers invoke this method periodically from compression or extraction loops to expose how
   * many bytes have been read from the input and written to the output so far. Implementations
   * should avoid expensive work, because this callback may be executed in performance-sensitive
   * contexts or under synchronization. Results are cumulative, not deltas, and callers are expected
   * to keep counts consistent between invocations.
   *
   * <p>Typical usage forwards the data to a progress bar, a statistics collector, or a cancel
   * signal checker:
   *
   * <pre>{@code
   * progress.setProgress(bytesRead, bytesWritten);
   * }</pre>
   *
   * @param inSize cumulative number of bytes consumed from the input source; should increase
   *     monotonically as processing advances and may equal the final input size when complete
   * @param outSize cumulative number of bytes produced to the output sink; expected to reflect
   *     total written bytes to date, even when the final output size is not yet known
   */
  void setProgress(long inSize, long outSize);
}
