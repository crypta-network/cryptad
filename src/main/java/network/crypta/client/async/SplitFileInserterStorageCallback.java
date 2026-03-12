package network.crypta.client.async;

import network.crypta.client.InsertException;
import network.crypta.client.Metadata;

/**
 * Callback interface used by {@link SplitFileInserterStorage} to notify higher layers about
 * progress and outcomes during a split-file insert.
 *
 * <p>This interface decouples storage/encoding concerns from orchestration and user-facing
 * lifecycle management. Implementations are typically provided by {@link SplitFileInserter}, which
 * coordinates block encoding, key discovery, and scheduling via {@link SplitFileInserterSender}.
 * Tests or tools may implement this interface to simulate caller behavior or to observe encoding
 * milestones without driving a full network insert.
 *
 * <p>Callbacks are issued as storage completes distinct phases: when encoding begins and finishes
 * per segment, when all keys are known, as individual blocks are inserted, and when the overall
 * insert either succeeds or fails. An implementation should be prepared to make scheduling
 * decisions in response (for example, starting the next level once keys are available), to update
 * UI/state, and to release resources on terminal outcomes. Unless stated otherwise by the caller,
 * implementations are not required to be thread-safe; callbacks are invoked in the context of the
 * storage/inserter job system.
 *
 * <ul>
 *   <li>Progress: segment-level encode notifications enable incremental scheduling.
 *   <li>Keys: {@link #onHasKeys()} fires once all block keys are available for selection.
 *   <li>Success/failure: terminal outcomes include final {@link Metadata} on success or an {@link
 *       network.crypta.client.InsertException} on failure.
 * </ul>
 *
 * @author toad
 * @see SplitFileInserter
 * @see SplitFileInserterStorage
 * @see SplitFileInserterSender
 */
public interface SplitFileInserterStorageCallback {

  /**
   * All segments (including any cross-segment redundancy) have finished encoding.
   *
   * <p>This indicates that the storage layer has produced all data and check blocks and persisted
   * any required status so that a resume can safely continue from this point. Implementations may
   * use this signal to adjust scheduling, throttle further CPU work, or prioritize network sends,
   * since no additional encoding work remains. This callback does not imply that keys are already
   * exposed to the caller; see {@link #onHasKeys()} for the point at which all block keys are
   * available for higher-level decisions.
   */
  void onFinishedEncode();

  /**
   * Called after completing encoding (data and check blocks) for a single segment.
   *
   * <p>Implementations can treat this as an incremental progress hook: additional blocks are now
   * available to schedule for insertion, and callers may choose to rescan queues, update progress
   * indicators, or opportunistically start the next level. After every segment has been reported at
   * least once through this method, {@link #onHasKeys()} will be invoked to signal that the full
   * set of block keys is known.
   */
  void encodingProgress();

  /**
   * All segments have been encoded and every block now has an assigned CHK.
   *
   * <p>At this point, the implementation has the complete key set and can decide whether to
   * finalize the current level, begin the next level (for multi-level metadata or manifests), or
   * continue inserting the remaining blocks first. This is a pivotal scheduling decision: callers
   * that wish to surface early metadata may choose to proceed immediately, while others may prefer
   * to await a higher fraction of successful inserts to reduce perceived latency on subsequent
   * fetches.
   */
  void onHasKeys();

  /**
   * Called when the entire insert succeeds and all blocks have been accepted.
   *
   * <p>This is the terminal success signal for the split-file operation. At this point, the
   * implementation can persist or present the final metadata, free buffers, and notify user code
   * that the insert is durably complete. The argument is immutable from the callback’s perspective;
   * callers should copy values as needed for long-term retention. Implementations should avoid
   * throwing from this callback.
   *
   * @param metadata the resulting {@link Metadata} for the inserted content, including split-file
   *     parameters and any top-level descriptor details; never {@code null} when invoked
   */
  void onSucceeded(Metadata metadata);

  /**
   * Called when the insert fails for any reason after encoding has finished.
   *
   * <p>All segment encodes have completed by the time this method is invoked, so failures reflect
   * network conditions, collisions, validation errors, or similar problems surfaced by the
   * insertion pipeline. Implementations should record details, update UI/state, and perform
   * cleanup. The error mode on the exception indicates whether retrying is useful.
   *
   * @param e the {@link InsertException} describing the failure mode and optional detail message;
   *     never {@code null}; inspect {@link InsertException#getMode()} to determine retryability
   */
  void onFailed(InsertException e);

  /**
   * Called when an individual block is inserted successfully.
   *
   * <p>This fine-grained signal enables progress tracking and backpressure tuning. Implementations
   * might count successes to drive UI updates, unblock dependent work, or adapt retry strategies.
   * Failures are surfaced via {@link #onFailed(InsertException)}; this callback is only for success
   * of a single block and does not imply overall completion.
   */
  void onInsertedBlock();

  /**
   * Called when a block becomes fetchable for peers due to network propagation or cache state.
   *
   * <p>Implementations can use this to clear any local cooldown or backoff associated with that
   * block and to consider rescheduling dependent work. When the change originates from completing
   * an encode, {@link #encodingProgress()} is preferred and this method is not invoked.
   */
  void clearCooldown();

  /**
   * Returns the request priority class used for encoding/scheduling jobs within the inserter.
   *
   * <p>The value is typically provided by the client context and influences how jobs compete for
   * resources inside the node (for example, real-time vs. background work queues). Implementations
   * should return a stable value for the lifetime of a single insert.
   *
   * @return a small integral priority class understood by the client scheduler; higher classes may
   *     be treated as more urgent, but the precise mapping is node-implementation specific
   */
  short getPriorityClass();
}
