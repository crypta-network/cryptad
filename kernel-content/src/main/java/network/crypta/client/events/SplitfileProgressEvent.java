package network.crypta.client.events;

import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reports incremental progress while fetching or inserting a split file.
 *
 * <p>A split file operation breaks a large item into fixed-size blocks which are processed
 * independently by the client. Instances of this event convey the current counts of total blocks,
 * successfully processed blocks, and failures (both retryable and fatal). The event is immutable
 * from the perspective of callers; values represent a snapshot at the time of creation. Typical
 * listeners use these snapshots to compute a coarse progress percentage and to present user-facing
 * progress information.
 *
 * <p>The event does not perform any I/O on its own. It is created by request coordinators and
 * dispatched through the client event bus to interested consumers. It may be emitted frequently for
 * long-running operations. Callers should therefore avoid heavy processing in listeners.
 *
 * <p>Thread-safety: event instances are safely published and read-only. Consumers may freely access
 * the fields without additional synchronization, but should avoid mutating referenced values such
 * as {@link #latestSuccess} and {@link #latestFailure} (immutable instants are stored on
 * construction).
 *
 * <ul>
 *   <li>Progress accounting: {@link #succeedBlocks}, {@link #failedBlocks}, and {@link
 *       #fatallyFailedBlocks} are disjoint subsets of {@link #totalBlocks}.
 *   <li>Completion threshold: {@link #getMinSuccessfulBlocks()} indicates when the higher-level
 *       operation can be considered complete.
 *   <li>Totals: {@link #finalizedTotal} signals whether the total block count is definitive.
 * </ul>
 */
public class SplitfileProgressEvent implements ClientEvent {
  private static final Logger LOG = LoggerFactory.getLogger(SplitfileProgressEvent.class);

  /** Event code used on the client event bus to identify this event type. */
  public static final int CODE = 0x07;

  /**
   * Total number of blocks involved in the operation. The value may be provisional while the client
   * is still discovering the full split map; see {@link #finalizedTotal} for stability.
   */
  public final int totalBlocks;

  /**
   * Number of blocks that have been processed successfully so far. This count never decreases and
   * is typically used to derive a progress percentage relative to {@link
   * #getMinSuccessfulBlocks()}.
   */
  public final int succeedBlocks;

  /**
   * Timestamp of the latest successful block completion. When unavailable, this value is {@code
   * null}.
   *
   * <p>The timestamp is supplied by the producing request component and represents the most recent
   * successful block observed when this snapshot was created.
   */
  public final Instant latestSuccess;

  /**
   * Number of blocks that have failed but may still be retried by the scheduler. Retries can
   * succeed later depending on routing and peer availability.
   */
  public final int failedBlocks;

  /**
   * Number of blocks that have failed permanently and will not be retried by the client. Fatal
   * failures contribute to overall progress but reduce the chance of completing the operation.
   */
  public final int fatallyFailedBlocks;

  /**
   * Timestamp of the latest block failure. When unavailable, this value is {@code null}.
   *
   * <p>The timestamp is supplied by the producing request component and represents the most recent
   * failed block observed when this snapshot was created.
   */
  public final Instant latestFailure;

  /**
   * Minimum number of fetchable blocks for the current split context. This value reflects the
   * fetch-side threshold and may differ from {@link #getMinSuccessfulBlocks()} when policy requires
   * a higher success count to assemble the final artifact.
   */
  public final int minSuccessFetchBlocks;

  private int minSuccessfulBlocks;

  /**
   * Whether {@link #totalBlocks} is final. When {@code false}, the client may still discover
   * additional blocks; when {@code true}, the total is definitive.
   */
  public final boolean finalizedTotal;

  /**
   * Creates a new snapshot of splitfile progress.
   *
   * <p>All counts are non-negative. Timestamp values may be {@code null} when no corresponding
   * event has occurred. Instants are stored directly because they are immutable.
   *
   * @param counts numeric progress counters for the splitfile operation
   * @param timestamps latest success and failure timestamps, or {@code null} values when unknown
   */
  public SplitfileProgressEvent(
      SplitfileProgressCounts counts, SplitfileProgressTimestamps timestamps) {
    this.totalBlocks = counts.totalBlocks();
    this.succeedBlocks = counts.succeedBlocks();
    this.latestSuccess = timestamps.latestSuccess();
    this.failedBlocks = counts.failedBlocks();
    this.fatallyFailedBlocks = counts.fatallyFailedBlocks();
    this.latestFailure = timestamps.latestFailure();
    this.minSuccessfulBlocks = counts.minSuccessfulBlocks();
    this.finalizedTotal = counts.finalizedTotal();
    this.minSuccessFetchBlocks = counts.minSuccessFetchBlocks();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Created SplitfileProgressEvent: total={} succeed={} failed={} fatally={} min success={}"
              + " finalized={}",
          totalBlocks,
          succeedBlocks,
          failedBlocks,
          fatallyFailedBlocks,
          minSuccessfulBlocks,
          finalizedTotal);
  }

  /**
   * No-arg constructor for serialization frameworks. Initializes an empty, non-finalized progress
   * snapshot with zero counts. {@link #latestSuccess} is set to the current time to preserve
   * historical semantics in callers that assume a non-null success timestamp.
   */
  protected SplitfileProgressEvent() {
    // For serialization support.
    totalBlocks = 0;
    succeedBlocks = 0;
    // Historical semantics preserve a non-null default success timestamp.
    latestSuccess = Instant.now();
    failedBlocks = 0;
    fatallyFailedBlocks = 0;
    latestFailure = null;
    minSuccessFetchBlocks = 0;
    finalizedTotal = false;
  }

  /**
   * Returns the minimum number of successful blocks required to complete the higher-level
   * operation.
   *
   * <p>The value represents a completion threshold rather than a percentage. When {@link
   * #succeedBlocks} reaches or exceeds this number, the client can typically assemble the output or
   * otherwise finalize the request.
   *
   * @return a non-negative threshold count indicating when progress is enough to finish; the value
   *     does not change for a given event instance
   */
  public int getMinSuccessfulBlocks() {
    return minSuccessfulBlocks;
  }

  /**
   * Human-readable progress summary for logging and diagnostic display.
   *
   * <p>The returned string includes percentages and block counts. It is intended for developers and
   * tools rather than for end-user UI localization.
   *
   * @return a single-line summary describing successes, failures, totals, and thresholds
   */
  @Override
  public String getDescription() {
    StringBuilder sb = new StringBuilder();
    sb.append("Completed ");
    if ((minSuccessfulBlocks == 0) && (succeedBlocks == 0)) minSuccessfulBlocks = 1;
    if (minSuccessfulBlocks == 0) {
      if (LOG.isDebugEnabled())
        LOG.error(
            "minSuccessfulBlocks=0, succeedBlocks={}, totalBlocks={}, failedBlocks={},"
                + " fatallyFailedBlocks={}, finalizedTotal={}",
            succeedBlocks,
            totalBlocks,
            failedBlocks,
            fatallyFailedBlocks,
            finalizedTotal,
            new Exception("debug"));
      else
        LOG.error(
            "minSuccessfulBlocks=0, succeedBlocks={}, totalBlocks={}, failedBlocks={},"
                + " fatallyFailedBlocks={}, finalizedTotal={}",
            succeedBlocks,
            totalBlocks,
            failedBlocks,
            fatallyFailedBlocks,
            finalizedTotal);
    } else {
      sb.append(100 * succeedBlocks / minSuccessfulBlocks);
      sb.append('%');
    }
    sb.append(' ');
    sb.append(succeedBlocks);
    sb.append('/');
    sb.append(minSuccessfulBlocks);
    sb.append(" (failed ");
    sb.append(failedBlocks);
    sb.append(", fatally ");
    sb.append(fatallyFailedBlocks);
    sb.append(", total ");
    sb.append(totalBlocks);
    sb.append(", minSuccessFetch ");
    sb.append(minSuccessFetchBlocks);
    sb.append(") ");
    sb.append(finalizedTotal ? " (finalized total)" : "");
    return sb.toString();
  }

  /**
   * Returns the integer code that identifies this event on the client event bus.
   *
   * @return the stable event code constant associated with this event type
   */
  @Override
  public int getCode() {
    return CODE;
  }
}
