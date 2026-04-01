package network.crypta.runtime.admin.queue.page;

import java.time.Instant;
import network.crypta.keys.FreenetURI;

/**
 * Describes the minimal runtime-owned view of a queue entry needed by the legacy queue page.
 *
 * <p>The interface deliberately mirrors only the read-only fields currently consumed by {@code
 * LegacyQueuePagePort}: identifiers, progress counters, persistence flags, timestamps, failure
 * text, and the canonical URI used in the existing HTML. It is not intended to be a general queue
 * domain model.
 *
 * <p>Implementations usually adapt the live request state from another subsystem. Callers should
 * treat each accessor as presentation data for one queue snapshot, not as a mutable handle they can
 * use to control the request. The methods remain narrow on purpose, so later refactors can move the
 * queue page away from FCP details without widening the runtime-owned surface again.
 */
public interface QueuePageRequestView {
  /**
   * Returns the stable queue identifier associated with this request.
   *
   * @return queue identifier text used in forms, actions, and diagnostics
   */
  String getIdentifier();

  /**
   * Indicates whether the request has completed successfully.
   *
   * @return {@code true} when the request reached a successful terminal state
   */
  boolean hasSucceeded();

  /**
   * Indicates whether the request has reached any terminal state.
   *
   * @return {@code true} when the request is finished, regardless of success or failure
   */
  boolean hasFinished();

  /**
   * Returns the current scheduler priority for the request.
   *
   * @return priority value used for queue ordering and display
   */
  short getPriority();

  /**
   * Returns the currently known total block count for the request.
   *
   * @return total block count visible to the queue page in this snapshot
   */
  int getTotalBlocks();

  /**
   * Indicates whether the total block count is final rather than provisional.
   *
   * @return {@code true} when {@link #getTotalBlocks()} will no longer increase
   */
  boolean isTotalFinalized();

  /**
   * Returns the minimum block success threshold needed for completion.
   *
   * @return minimum successful block count required to satisfy the request
   */
  int getMinBlocks();

  /**
   * Returns the number of blocks fetched or inserted successfully so far.
   *
   * @return successful block count visible in the current queue snapshot
   */
  int getFetchedBlocks();

  /**
   * Returns the most recent successful activity timestamp for this request.
   *
   * @return last success instant, or {@code null} when no success has been recorded
   */
  Instant getLastSuccess();

  /**
   * Returns the most recent failure timestamp for this request.
   *
   * @return last failure instant, or {@code null} when no failure has been recorded
   */
  Instant getLastFailure();

  /**
   * Returns the canonical request URI used by the queue page for display and grouping.
   *
   * @return request URI associated with this queue entry, or {@code null} when unavailable
   */
  FreenetURI getUri();

  /**
   * Returns the current data-size estimate associated with this request.
   *
   * @return request data size in bytes, using the semantics of the adapted backend
   */
  long getDataSize();

  /**
   * Indicates whether the request is stored in the persistent queue.
   *
   * @return {@code true} when the request survives ordinary daemon restarts
   */
  boolean isPersistent();

  /**
   * Indicates whether the request is marked as persistent forever.
   *
   * @return {@code true} when the request uses the strongest persistent lifetime
   */
  boolean isPersistentForever();

  /**
   * Returns the number of permanently failed blocks recorded for the request.
   *
   * @return fatal block failure count used in advanced queue diagnostics
   */
  int getFatalyFailedBlocks();

  /**
   * Returns the number of retryable block failures recorded for the request.
   *
   * @return non-fatal block failure count visible to the queue page
   */
  int getFailedBlocks();

  /**
   * Indicates whether the request has started doing work yet.
   *
   * @return {@code true} once the request moved past its initial waiting state
   */
  boolean isStarted();

  /**
   * Returns the current failure description in either short or long form.
   *
   * @param longDescription {@code true} to request a more detailed explanation when supported
   * @return failure description text, or {@code null} when no failure message is available
   */
  String getFailureReason(boolean longDescription);

  /**
   * Returns the sanitized preferred filename derived for display.
   *
   * @return safe filename text for queue-page columns, or {@code null} when none is known
   */
  String getPreferredFilenameSafe();
}
