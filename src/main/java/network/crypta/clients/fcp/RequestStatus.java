package network.crypta.clients.fcp;

import java.util.Date;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;

/**
 * Captures the life-cycle snapshot of a single Freenet Client Protocol request.
 *
 * <p>A {@code RequestStatus} combines high-level state (started, finished, success) with granular
 * counters, timestamps, and persistence policies so higher layers can render progress without
 * blocking the database thread. Instances arise when users schedule fetches/inserts or when
 * persisted jobs are reloaded at startup, and they are subsequently mutated only by the owning
 * request code paths.
 *
 * <p>The class is deliberately abstract: subclasses specify transport-specific details such as the
 * originating {@link FreenetURI}, failure descriptions, and data sizing. Implementations are
 * expected to snapshot themselves via {@link #copy()} so callers can access status objects outside
 * synchronization blocks without risking torn reads. Unless noted otherwise, getters may be safely
 * invoked from any thread that already coordinates with {@code RequestStatusCache}.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> expose immutable identifiers, mutable priority, and
 *       completion metadata.
 *   <li><strong>Concurrency:</strong> mutation methods synchronize on {@code this}; readers mirror
 *       that discipline for the guarded fields.
 *   <li><strong>Persistence:</strong> {@link #isPersistentForever()} and {@link #isPersistent()}
 *       describe whether the request survives client restarts.
 * </ul>
 *
 * @author toad
 * @see RequestStatusCache
 */
public abstract class RequestStatus {

  private final String identifier;
  private boolean hasStarted;
  private boolean hasFinished;
  private boolean hasSucceeded;
  private short priority;
  private int totalBlocks;
  private int minBlocks;
  private int fetchedBlocks;

  /** Timestamp of the most recent successful block or completion event. */
  private Date latestSuccess;

  private int fatallyFailedBlocks;
  private int failedBlocks;
  /* @see ClientRequester#latestFailure */
  private Date latestFailure;
  private boolean isTotalFinalized;
  private final Persistence persistence;

  /**
   * The download or upload has finished.
   *
   * @param success Did it succeed?
   */
  synchronized void setFinished(boolean success) {
    this.latestSuccess = new Date();
    this.hasFinished = true;
    this.hasSucceeded = success;
    this.hasStarted = true;
    this.isTotalFinalized = true;
  }

  @SuppressWarnings("SameParameterValue")
  synchronized void restart(boolean started) {
    // See ClientRequester.getLatestSuccess() for why this defaults to the current time.
    this.latestSuccess = new Date();
    this.hasFinished = false;
    this.hasSucceeded = false;
    this.hasStarted = started;
    this.isTotalFinalized = false;
  }

  /**
   * Creates a mutable status holder from a preassembled snapshot.
   *
   * <p>Callers typically invoke this constructor while wiring {@code ClientRequest} instances at
   * submission time or when replaying stored jobs on startup. Each supplied metric is immediately
   * copied into a guarded field, and mutable timestamps are cloned to prevent accidental sharing.
   * The constructor does not perform validation beyond storing the snapshots, so upstream code must
   * ensure that block counts and flags reflect the latest durable state.
   *
   * @param snapshot bundle containing the base request status fields.
   */
  RequestStatus(RequestStatusSnapshot snapshot) {
    this.identifier = snapshot.identifier();
    this.persistence = snapshot.persistence();
    this.hasStarted = snapshot.started();
    this.hasFinished = snapshot.finished();
    this.hasSucceeded = snapshot.success();
    this.priority = snapshot.priority();
    this.totalBlocks = snapshot.total();
    this.minBlocks = snapshot.min();
    this.fetchedBlocks = snapshot.fetched();
    // clone() because Date is mutable
    this.latestSuccess =
        snapshot.latestSuccess() != null ? (Date) snapshot.latestSuccess().clone() : null;
    this.fatallyFailedBlocks = snapshot.fatal();
    this.failedBlocks = snapshot.failed();
    // clone() because Date is mutable
    this.latestFailure =
        snapshot.latestFailure() != null ? (Date) snapshot.latestFailure().clone() : null;
    this.isTotalFinalized = snapshot.totalFinalized();
  }

  /**
   * Builds a defensive copy of another status instance so subclasses can expose snapshots.
   *
   * <p>The constructor copies every scalar, clones, mutable timestamps, and intentionally omits any
   * shared references so callers can retain the resulting object beyond internal synchronization
   * windows. Subclasses typically delegate to this constructor within their own {@link #copy()}
   * implementation before adding subclass-specific state.
   *
   * @param source reference status whose fields should be mirrored without sharing mutable
   *     structures or synchronization guards.
   */
  protected RequestStatus(RequestStatus source) {
    this.identifier = source.identifier;
    this.persistence = source.persistence;
    this.hasStarted = source.hasStarted;
    this.hasFinished = source.hasFinished;
    this.hasSucceeded = source.hasSucceeded;
    this.priority = source.priority;
    this.totalBlocks = source.totalBlocks;
    this.minBlocks = source.minBlocks;
    this.fetchedBlocks = source.fetchedBlocks;
    this.latestSuccess = source.latestSuccess != null ? (Date) source.latestSuccess.clone() : null;
    this.fatallyFailedBlocks = source.fatallyFailedBlocks;
    this.failedBlocks = source.failedBlocks;
    this.latestFailure = source.latestFailure != null ? (Date) source.latestFailure.clone() : null;
    this.isTotalFinalized = source.isTotalFinalized;
  }

  /**
   * Reports whether the associated client request already completed successfully.
   *
   * <p>The flag flips to {@code true} only once {@link #setFinished(boolean)} commits a successful
   * terminal state, and it remains true for the lifetime of this instance even if the client
   * restarts. Because UI layers poll this method frequently, it simply returns the cached boolean
   * without synchronization, relying on callers to coordinate through {@code RequestStatusCache}
   * when stricter happens-before guarantees are required.
   *
   * @return {@code true} when the request reached a successful terminal state; {@code false} while
   *     pending or failed.
   */
  public boolean hasSucceeded() {
    return hasSucceeded;
  }

  /**
   * Indicates whether the request finished, regardless of outcome.
   *
   * <p>The value turns {@code true} as soon as {@link #setFinished(boolean)} executes, even before
   * listeners observe the final result, and remains latched until {@link #restart(boolean)} runs.
   * Poll this method to decide when to stop rendering progress indicators or when it is safe to
   * emit final notifications to remote clients.
   *
   * @return {@code true} when the tracked operation is no longer running; {@code false} otherwise.
   */
  public boolean hasFinished() {
    return hasFinished;
  }

  /**
   * Returns the current scheduler priority associated with the request.
   *
   * <p>The value is read under synchronization because {@link #setPriority(short)} may be invoked
   * concurrently by operators manually reprioritizing downloads. Higher numbers generally represent
   * higher priority within the queue, but the exact semantics depend on the upstream scheduler.
   * Consumers can compare this number against policy thresholds to categorize requests.
   *
   * @return priority level currently assigned to the request, typically within the user-configured
   *     bounds.
   */
  public synchronized short getPriority() {
    return priority;
  }

  /**
   * Retrieves the stable external identifier backing this status entry.
   *
   * <p>The identifier is the token exchanged over FCP and stored inside caches, so UI components or
   * remote clients can match asynchronous events to the originating submission. Identifiers are
   * opaque, case-sensitive strings; treat them as stable handles rather than deriving semantics
   * from their contents.
   *
   * @return immutable identifier string chosen at request creation time.
   */
  public String getIdentifier() {
    return identifier;
  }

  /**
   * Provides the latest known total block count for the request.
   *
   * <p>The total may increase as splitfile metadata becomes available. Once {@link
   * #isTotalFinalized()} is true the figure matches the final number of transfers, enabling
   * accurate percentage calculations and disk predictions. Until then, treat the number as a moving
   * target and update progress displays dynamically.
   *
   * @return the number of blocks expected for the operation; may be zero while unknown.
   */
  public int getTotalBlocks() {
    return totalBlocks;
  }

  /**
   * States whether {@link #getTotalBlocks()} is final or still provisional.
   *
   * <p>Splitfile fetches often discover additional segments after the first metadata blocks arrive.
   * When this method returns {@code true}, consumers can rely on {@code totalBlocks} staying
   * constant for the remainder of the request and may safely cache derived estimates without
   * recomputing denominators every tick.
   *
   * @return {@code true} when the total block count will no longer change.
   */
  public boolean isTotalFinalized() {
    return isTotalFinalized;
  }

  /**
   * Returns the minimum number of blocks that must succeed for completion.
   *
   * <p>Some insert/fetch operations use redundancy; they may finish once a threshold is met even if
   * {@link #getTotalBlocks()} is larger. This target originates from the splitter metadata and
   * usually remains fixed, so comparing it with {@link #getFetchedBlocks()} reveals how close the
   * request is to meeting its redundancy goals.
   *
   * @return required minimum of successful blocks before declaring overall success.
   */
  public int getMinBlocks() {
    return minBlocks;
  }

  /**
   * Reports how many blocks already succeeded.
   *
   * <p>This counter increments as {@link SplitfileProgressEvent} notifications arrive and is the
   * primary input for user-facing progress indicators. It monotonically increases until completion
   * or cancellation and easily represents very large splitfiles because it is stored as a 32-bit
   * integer.
   *
   * @return number of blocks reported as successfully fetched or inserted thus far.
   */
  public int getFetchedBlocks() {
    return fetchedBlocks;
  }

  /**
   * Returns a defensive copy of the last success timestamp.
   *
   * <p>The timestamp records the moment when the most recent block, or the whole request,
   * succeeded. A {@code null} value indicates that no successes have occurred yet. Callers receive
   * a clone to avoid mutating internal state and may safely retain the returned {@link Date} for
   * formatting or auditing purposes.
   *
   * @return cloned {@link Date} of the last success, or {@code null} if none occurred.
   */
  public Date getLastSuccess() {
    // clone() because Date is mutable.
    return latestSuccess != null ? (Date) latestSuccess.clone() : null;
  }

  /**
   * Returns a defensive copy of the most recent failure timestamp.
   *
   * <p>The value is updated whenever {@link #updateStatus(SplitfileProgressEvent)} records a fatal
   * or transient failure. A {@code null} timestamp indicates a failure-free run so far. The clone
   * is safe to retain beyond the lifespan of the status object and is suitable for logging or
   * alerting without additional synchronization.
   *
   * @return cloned {@link Date} representing the last failure, or {@code null} if nothing failed.
   */
  public Date getLastFailure() {
    // clone() because Date is mutable.
    return latestFailure != null ? (Date) latestFailure.clone() : null;
  }

  /**
   * Returns the canonical {@link FreenetURI} related to this request.
   *
   * <p>Fetch requests report their original key, while insert requests typically report the final
   * key assigned by the network once the data becomes addressable. Implementations must guarantee
   * that the returned URI accurately identifies the user-visible resource because UI and logging
   * layers surface it directly to end users.
   *
   * @return immutable Freenet URI representing the resource being transferred.
   */
  public abstract FreenetURI getURI();

  /**
   * Provides the expected payload size expressed in bytes.
   *
   * <p>Depending on the request type, this value may come from manifest metadata or from a known
   * insert source. Subclasses should return {@code -1} when the size is unknown. Callers use the
   * information to preallocate disk space, enforce quotas, and display human-readable progress
   * indicators with estimated time remaining.
   *
   * @return non-negative number of bytes when known, or {@code -1} if indeterminate.
   */
  public abstract long getDataSize();

  /**
   * Indicates whether the request is configured to persist indefinitely across restarts.
   *
   * <p>Requests marked {@link Persistence#FOREVER} remain queued until they succeed or are manually
   * canceled. Use this helper to distinguish between opportunistic and durable queue entries and to
   * surface warnings when users attempt to delete persistent jobs.
   *
   * @return {@code true} if the persistence policy equals {@link Persistence#FOREVER}.
   */
  public boolean isPersistentForever() {
    return persistence == Persistence.FOREVER;
  }

  /**
   * States whether the request survives beyond the current FCP connection.
   *
   * <p>Persistent requests may be resumed after reconnecting, while {@link Persistence#CONNECTION}
   * requests are automatically cleaned up when the client disconnects. UI layers use this flag to
   * filter short-lived jobs and to warn users that connection-bound requests will disappear when
   * the session closes.
   *
   * @return {@code true} if the underlying persistence policy is not {@link
   *     Persistence#CONNECTION}.
   */
  public boolean isPersistent() {
    return persistence != Persistence.CONNECTION;
  }

  /**
   * Returns how many blocks have failed irrecoverably.
   *
   * <p>Fatal failures usually indicate data corruption or exceeding retry limits. Once recorded,
   * they count against {@link #getMinBlocks()} and are never retried. Monitoring tools can use the
   * value to escalate user prompts when recovery appears impossible and to recommend cancelling the
   * job if redundancy has been exhausted.
   *
   * @return count of permanently failed blocks for the request.
   */
  public int getFatalyFailedBlocks() {
    return fatallyFailedBlocks;
  }

  /**
   * Returns the number of blocks that failed but may still succeed on retry.
   *
   * <p>Splitfile processing often experiences transient failures due to routing issues. These are
   * captured here until a retry resolves them, or they transition into fatal failures. Operators
   * can compare this counter with the number of running retries to gauge whether additional
   * bandwidth is required.
   *
   * @return count of retryable failed blocks currently tracked.
   */
  public int getFailedBlocks() {
    return failedBlocks;
  }

  /**
   * Indicates whether the request lifecycle has already started transferring data.
   *
   * <p>The value is synchronized because {@link #setStarted(boolean)} may toggle it under lock
   * while state transitions occur. Callers can use the flag to distinguish between queued and
   * actively running jobs for display or scheduling purposes.
   *
   * @return {@code true} when the request progressed beyond submission; {@code false} otherwise.
   */
  public synchronized boolean isStarted() {
    return hasStarted;
  }

  /**
   * Returns a human-readable explanation for the latest failure.
   *
   * <p>Implementations should provide concise summaries when {@code longDescription} is {@code
   * false} and more verbose diagnostics otherwise. The text is typically surfaced in user-visible
   * logs or protocol replies and should therefore avoid leaking sensitive information. Where
   * possible, include actionable hints such as retry advice or error tokens that map to help pages.
   *
   * @param longDescription {@code true} to request detailed diagnostics; {@code false} for concise
   *     summaries.
   * @return explanatory text describing the failure state, or {@code null} when unknown.
   */
  public abstract String getFailureReason(boolean longDescription);

  /**
   * Applies a {@link SplitfileProgressEvent} snapshot to this status while holding the monitor.
   *
   * <p>The method copies counters and timestamp clones from the event, ensuring that listeners see
   * up-to-date block statistics and lifecycle information. Callers must already ensure that events
   * arrive in order for a given request because this method assumes monotonic progress when
   * updating fields such as {@link #minBlocks} and {@link #totalBlocks}.
   *
   * @param event event emitted by the splitter describing current block, failure, and success
   *     counts; must not be {@code null}.
   */
  public synchronized void updateStatus(SplitfileProgressEvent event) {
    this.failedBlocks = event.failedBlocks;
    this.fatallyFailedBlocks = event.fatallyFailedBlocks;
    // clone() because Date is mutable
    this.latestFailure = event.latestFailure != null ? (Date) event.latestFailure.clone() : null;
    this.fetchedBlocks = event.succeedBlocks;
    // clone() because Date is mutable
    this.latestSuccess = event.latestSuccess != null ? (Date) event.latestSuccess.clone() : null;
    this.isTotalFinalized = event.finalizedTotal;
    this.minBlocks = event.getMinSuccessfulBlocks();
    this.totalBlocks = event.totalBlocks;
  }

  /**
   * Updates the scheduler priority while holding the intrinsic lock.
   *
   * <p>Invocations originate from user commands or automatic QoS adjustments. The value takes
   * effect immediately for later queue decisions, so callers should avoid oscillating the priority
   * rapidly. No validation is performed beyond storing the primitive; schedulers interpret the
   * numeric range according to their own policy documents.
   *
   * @param newPriority priority value to commit verbatim; callers must keep it within configured
   *     bounds.
   */
  public synchronized void setPriority(short newPriority) {
    this.priority = newPriority;
  }

  /**
   * Marks whether the request has begun execution.
   *
   * <p>The flag usually transitions to {@code true} when the worker thread picks up the job and may
   * be reset via {@link #restart(boolean)}. Because external observers may poll {@link
   * #isStarted()}, the change occurs under synchronization, ensuring that readers never observe
   * half-applied transitions.
   *
   * @param started {@code true} when work has begun; {@code false} when queued.
   */
  public synchronized void setStarted(boolean started) {
    this.hasStarted = started;
  }

  /**
   * Resolves the best-effort filename associated with the request.
   *
   * <p>Implementations may derive the value from URI metadata, client-provided hints, or bundle
   * manifests. Return {@code null} when no meaningful filename is available, and avoid embedding
   * directory separators so callers can use the value directly for display or export prompts.
   * Implementations may also normalize whitespace to keep UI layout predictable across locales.
   *
   * @return preferred filename or {@code null} when insufficient information exists.
   */
  public abstract String getPreferredFilename();

  /**
   * Returns a non-null filename suitable for UI display or local storage prompts.
   *
   * <p>This helper delegates to {@link #getPreferredFilename()} and substitutes a localized
   * placeholder when the request lacks naming metadata. It never throws and therefore simplifies UI
   * code that merely needs some label while the transfer is pending, even for requests that never
   * revealed a meaningful name.
   *
   * @return filename from {@link #getPreferredFilename()} or a localized "unknown" placeholder.
   */
  public String getPreferredFilenameSafe() {
    String ret = getPreferredFilename();
    if (ret == null) return NodeL10n.getBase().getString("RequestStatus.unknownFilename");
    else return ret;
  }

  /**
   * Creates an immutable snapshot of this request status.
   *
   * <p>Subclasses must return a brand-new instance populated through the copy constructor so
   * callers can safely retain the snapshot outside internal locks. Implementations typically add
   * their own subclass-specific cloning semantics before returning the result, often copying URI
   * and payload metadata alongside the core fields stored here.
   *
   * @return fresh snapshot reflecting the state at invocation time.
   */
  public abstract RequestStatus copy();
}
