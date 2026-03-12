package network.crypta.clients.fcp;

import java.time.Instant;
import java.util.Objects;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Carries a snapshot of splitfile download progress from the node to a client over the FCP control
 * channel.
 *
 * <p>This message wraps a {@link SplitfileProgressEvent} so downstream consumers can inspect
 * aggregate counts such as total, succeeded, failed, and fatally failed blocks. It preserves the
 * original identifier supplied by the requester and records whether the progress applies to the
 * global queue. Instances are immutable after construction and reuse the provided event rather than
 * creating a defensive copy, so callers should avoid mutating the underlying event once the message
 * is created.
 *
 * <p>Typical usage involves the node emitting progress updates as long-running splitfile requests
 * advance. Clients can poll or subscribe to these messages to drive UI indicators or retry logic.
 * The computed field set intentionally omits potentially misleading transient failure counts until
 * upstream reporting is corrected. The class is not thread-safe; coordinate external
 * synchronization if a single instance is shared across threads while reading the encapsulated
 * event.
 *
 * <ul>
 *   <li>Identifier mapping ensures clients can correlate updates with the originating request.
 *   <li>Global flag communicates whether the request resides in the shared queue.
 *   <li>Timestamps use {@link java.time.Instant} for immutable time snapshots.
 * </ul>
 *
 * @see SplitfileProgressEvent
 * @see FCPMessage
 */
public class SimpleProgressMessage extends FCPMessage {

  private final String ident;
  private final boolean global;
  private final SplitfileProgressEvent event;

  /**
   * Creates a progress message bound to a request identifier and the originating splitfile progress
   * event.
   *
   * <p>The constructor retains a reference to the supplied {@link SplitfileProgressEvent} and uses
   * {@link Objects#requireNonNull(Object, String)} to guarantee it is present before the message is
   * transmitted. Callers should treat the event as effectively read-only after constructing the
   * message to avoid race conditions between producers and consumers that read derived field set
   * values.
   *
   * @param identifier unique caller-provided token used to correlate progress responses with the
   *     original request; may be {@code null} when correlation is unnecessary.
   * @param global flag indicating whether the tracked request resides in the global queue as
   *     opposed to a per-client queue; influences downstream routing decisions.
   * @param event splitfile progress snapshot supplying counts and timestamps; must be non-null and
   *     remain stable for the lifetime of this message instance.
   */
  public SimpleProgressMessage(String identifier, boolean global, SplitfileProgressEvent event) {
    this.ident = identifier;
    this.event = Objects.requireNonNull(event, "event");
    this.global = global;
  }

  /**
   * No-argument constructor reserved for deserialization frameworks that populate fields via
   * reflection.
   *
   * <p>The instance created through this path is incomplete until a {@link SplitfileProgressEvent}
   * is injected, and most accessors will throw {@link IllegalStateException} via {@link
   * #requireEvent()} if invoked prematurely. Application code should prefer the primary constructor
   * unless a serialization library mandates this signature.
   */
  @SuppressWarnings("unused")
  protected SimpleProgressMessage() {
    // For serialization.
    ident = null;
    global = false;
    event = null;
  }

  /**
   * Builds the field set representation expected by FCP clients for a progress update.
   *
   * <p>The generated {@link SimpleFieldSet} includes totals, required minimums, success counts, and
   * fatal failure counts derived directly from the underlying event. It clones timestamp fields
   * into millisecond epoch values and intentionally omits the {@code LastFailure} attribute because
   * the upstream event currently reports unreliable data for transient failures. Optional values
   * such as {@code MinSuccessFetchBlocks} are only present when non-zero to avoid inflating the
   * payload. The identifier and global flag are always emitted so clients can associate the update
   * with a specific request and queue context.
   *
   * @return mutable field set containing progress metrics suitable for wire transmission to FCP
   *     clients; callers may further augment or serialize it as needed.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SplitfileProgressEvent localEvent = requireEvent();
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("Total", localEvent.totalBlocks);
    fs.put("Required", localEvent.getMinSuccessfulBlocks());
    fs.put("Failed", localEvent.failedBlocks);
    fs.put("FatallyFailed", localEvent.fatallyFailedBlocks);
    /* The LastFailure field is intentionally omitted because the current event framework
     * reports 0 even when transient failures occur; see
     * https://bugs.freenetproject.org/view.php?id=6526. Re-enable once the upstream
     * limitation is addressed. */
    fs.put("Succeeded", localEvent.succeedBlocks);
    fs.put(
        "LastProgress",
        localEvent.latestSuccess != null ? localEvent.latestSuccess.toEpochMilli() : 0);
    fs.put("FinalizedTotal", localEvent.finalizedTotal);
    if (localEvent.minSuccessFetchBlocks != 0)
      fs.put("MinSuccessFetchBlocks", localEvent.minSuccessFetchBlocks);
    fs.putSingle("Identifier", ident);
    fs.put("Global", global);
    return fs;
  }

  /**
   * Returns the FCP message name used on the wire for this progress update.
   *
   * <p>The value is a stable constant ({@code "SimpleProgress"}) and is used by protocol handlers
   * to route or deserialize messages of this type. Because the name never varies, clients can rely
   * on it when filtering incoming messages without needing to inspect the payload contents.
   *
   * @return constant message name {@code "SimpleProgress"} that identifies this message class in
   *     FCP exchanges.
   */
  @Override
  public String getName() {
    return "SimpleProgress";
  }

  /**
   * Rejects inbound use of this message from clients by throwing a protocol error.
   *
   * <p>{@code SimpleProgress} messages are emitted by the node toward clients; receiving one from a
   * client indicates a misuse of the protocol. This method enforces that contract by immediately
   * raising {@link MessageInvalidException} with an {@link ProtocolErrorMessage#INVALID_MESSAGE}
   * code, preserving the identifier and global context for diagnostic logging downstream. The node
   * state remains unchanged because no side effects occur before the exception is thrown.
   *
   * @param handler connection handler representing the client session that attempted to send the
   *     message; not used because the method always fails fast.
   * @param node current node instance; retained for interface compatibility but unused in the
   *     rejection path.
   * @throws MessageInvalidException always thrown to signal that the message direction is invalid
   *     when initiated by a client.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "SimpleProgress goes from server to client not the other way around",
        ident,
        global);
  }

  /**
   * Computes the fraction of successfully fetched blocks relative to the reported total.
   *
   * <p>The value is derived by dividing {@code succeedBlocks} by {@code totalBlocks} from the
   * underlying event without additional rounding. If the event reports zero total blocks, the
   * result follows Java double division semantics ({@code NaN} or infinite). Callers should handle
   * these edge cases when presenting progress to end users. The returned value reflects the state
   * at the time the message was constructed and will not update if the original event later
   * changes.
   *
   * @return ratio of succeeded blocks to total blocks as a double precision value that may be
   *     {@code NaN} or infinite when totals are zero.
   */
  public double getFraction() {
    SplitfileProgressEvent localEvent = requireEvent();
    return (double) localEvent.succeedBlocks / (double) localEvent.totalBlocks;
  }

  /**
   * Reports the minimum number of successful blocks required for the splitfile operation to be
   * considered complete.
   *
   * <p>The value originates from {@link SplitfileProgressEvent#getMinSuccessfulBlocks()} and is
   * typically less than or equal to the total block count. This threshold reflects redundancy in
   * the encoding scheme and may guide UI components when estimating completion. The method performs
   * no validation beyond ensuring the encapsulated event is present; callers should treat negative
   * or unexpectedly large values as indicators of upstream misconfiguration rather than normalize
   * them here.
   *
   * @return minimum successful block count required for completion as reported by the event; value
   *     is not clamped or recalculated.
   */
  public double getMinBlocks() {
    return requireEvent().getMinSuccessfulBlocks();
  }

  /**
   * Exposes the total number of blocks the splitfile transfer expects to process.
   *
   * <p>This is a direct passthrough of {@code totalBlocks} from the underlying event and represents
   * the denominator for progress calculations. The message does not infer or recompute totals, so
   * it accurately reflects the event emitter's view, including any dynamic adjustments. Because the
   * value is returned as a {@code double}, callers can safely perform fractional arithmetic without
   * widening conversions.
   *
   * @return total block count required to satisfy the splitfile request at the time of capture.
   */
  public double getTotalBlocks() {
    return requireEvent().totalBlocks;
  }

  /**
   * Returns the number of blocks that have successfully completed so far.
   *
   * <p>The method mirrors the {@code succeedBlocks} field from the event and therefore shares its
   * semantics, including any re-fetches or retries accounted for by the producer. The count is
   * captured at message creation time and does not update afterward. Consumers should combine it
   * with {@link #getTotalBlocks()} or {@link #getFraction()} when rendering progress bars or
   * thresholds.
   *
   * @return count of completed blocks reported by the event without post-processing.
   */
  public double getFetchedBlocks() {
    return requireEvent().succeedBlocks;
  }

  /**
   * Retrieves the timestamp of the most recent successful block transfer, if any.
   *
   * <p>A {@code null} value indicates that no successful completion has been recorded yet.
   *
   * @return latest success timestamp, or {@code null} when no successes have occurred for this
   *     request.
   */
  public Instant getLatestSuccess() {
    SplitfileProgressEvent localEvent = requireEvent();
    return localEvent.latestSuccess;
  }

  /**
   * Provides the number of blocks that have encountered recoverable failures so far.
   *
   * <p>This value is taken directly from {@code failedBlocks} in the event and represents issues
   * that did not yet render the transfer unrecoverable. It may decrease over time as retries
   * succeed in upstream logic, but the message captures the value at creation time only. Callers
   * should interpret unusually large counts as a signal to surface more detailed diagnostics to
   * users.
   *
   * @return count of failed blocks that are not yet marked fatal as reported by the event.
   */
  public double getFailedBlocks() {
    return requireEvent().failedBlocks;
  }

  /**
   * Reports the number of blocks that have failed in a manner considered fatal by the fetch logic.
   *
   * <p>The method reflects {@code fatallyFailedBlocks} from the event and therefore mirrors the
   * emitter's definition of final failure. The misspelled method name is retained for API
   * stability; use caution when calling it from reflective or bean-mapped contexts. Because fatal
   * failures typically stop progress, consumers may want to halt retries or alert users when this
   * value is non-zero.
   *
   * @return count of blocks deemed fatally failed; zero implies no irrecoverable errors recorded.
   */
  public double getFatalyFailedBlocks() {
    return requireEvent().fatallyFailedBlocks;
  }

  /**
   * Returns the timestamp of the most recent failure event, whether recoverable or fatal.
   *
   * <p>When no failures have occurred, {@code null} is returned. Consumers should consider pairing
   * this value with {@link #getFailedBlocks()} or {@link #getFatalyFailedBlocks()} when diagnosing
   * recent instability.
   *
   * @return timestamp of the last recorded failure, or {@code null} if none are available.
   */
  public Instant getLatestFailure() {
    SplitfileProgressEvent localEvent = requireEvent();
    return localEvent.latestFailure;
  }

  /**
   * Indicates whether the total block count has been finalized by the upstream computation.
   *
   * <p>Some splitfile workflows adjust total counts during early discovery phases. This flag
   * mirrors {@code finalizedTotal} from the event and becomes {@code true} once the producer
   * declares the total stable. Consumers can use this signal to decide when to cache totals or when
   * to keep observing for changes before presenting a definitive progress bar.
   *
   * @return {@code true} when the total block count is stable; {@code false} if it may still
   *     change.
   */
  public boolean isTotalFinalized() {
    return requireEvent().finalizedTotal;
  }

  SplitfileProgressEvent getEvent() {
    return requireEvent();
  }

  private SplitfileProgressEvent requireEvent() {
    if (event == null) {
      throw new IllegalStateException("SplitfileProgressEvent is not initialized");
    }
    return event;
  }
}
