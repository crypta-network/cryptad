package network.crypta.client.async;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.Metadata;
import network.crypta.keys.BaseClientKey;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A lightweight healing queue that schedules opportunistic single-block insertions when the routing
 * position suggests it may improve availability.
 *
 * <p>This queue accepts already-prepared block data and arranges for asynchronous insertion of a
 * single content-hash key (CHK) block. Each call to {@link #queue} (or the internal {@code
 * innerQueue}) creates a dedicated single-block putter and, based on a healing decision supplied at
 * construction time, either schedules it immediately or declines the attempt. The number of
 * concurrent in-flight insertions is capped by a configured maximum.
 *
 * <p>Concurrency: calls that modify the internal state synchronize on the queue instance to update
 * the in-flight map and a simple counter used for diagnostics. The heavy-weight work (encoding and
 * network scheduling) runs asynchronously outside the critical section.
 *
 * <p>Lifecycle and persistence: this class participates in the standard client putter lifecycle
 * defined by its superclass, but its runtime helpers are transient and not restored on resume. In
 * other words, the queue itself is serializable for consistency with the broader client API, while
 * its internal, process-local bookkeeping is intentionally rebuilt at creation time.
 *
 * <ul>
 *   <li>Responsibilities: decide whether a block should be healed and, if so, schedule the insert.
 *   <li>Back-pressure: refuse new work when the concurrency cap is reached.
 *   <li>Resource handling: frees the provided bucket on success/failure via callbacks.
 * </ul>
 *
 * <p>Typical usage is to construct a queue with an insertion context and a decision supplier, then
 * call {@link #queue} for each candidate block.
 */
public class SimpleHealingQueue extends BaseClientPutter
    implements HealingQueue, PutCompletionCallback {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleHealingQueue.class);
  @Serial private static final long serialVersionUID = -2884613086588264044L;

  /**
   * Maximum number of concurrent in-flight healing insertions this queue permits.
   *
   * <p>The cap is enforced when accepting new work; attempts beyond this threshold are declined
   * immediately and not scheduled. The value is fixed for the lifetime of the queue instance.
   */
  final int maxRunning;

  /**
   * Monotonically increasing counter used to tag and correlate healing attempts in diagnostics.
   *
   * <p>The counter-value is assigned at enqueue time and may appear in debug log messages to aid
   * troubleshooting. It has no semantic meaning beyond identification.
   */
  int counter;

  /**
   * Insertion context applied to newly created single-block putters.
   *
   * <p>The context is supplied by the caller at construction time and shared by all insertions
   * created by this queue. It is expected to be valid for the entire queue lifetime.
   */
  InsertContext ctx;

  private final transient HealingDecisionSupplier healingDecisionSupplier;
  transient Map<Bucket, SingleBlockInserter> runningInserters;

  static final RequestClient REQUEST_CLIENT = new RequestClientBuilder().build();

  /**
   * Creates a healing queue with the given insertion context, priority, concurrency cap, and
   * decision supplier.
   *
   * <p>The queue does not take ownership of {@code context}. It evaluates whether to heal each
   * block using the supplied decision strategy and schedules accepted insertions asynchronously up
   * to {@code maxRunning} concurrent operations.
   *
   * @param context the insertion context to use for new single-block putters; must remain valid for
   *     the lifetime of this queue and is not copied.
   * @param prio the scheduling priority applied to created putters; higher values may be treated as
   *     more urgent by the client scheduler.
   * @param maxRunning the maximum number of in-flight healing insertions permitted at once; values
   *     less than one effectively prevent scheduling.
   * @param healingDecisionSupplier strategy used to decide whether a block at a given key location
   *     should be healed; queried for every candidate block.
   */
  public SimpleHealingQueue(
      InsertContext context,
      short prio,
      int maxRunning,
      HealingDecisionSupplier healingDecisionSupplier) {
    super(prio, REQUEST_CLIENT);
    this.ctx = context;
    this.healingDecisionSupplier = healingDecisionSupplier;
    this.runningInserters = new HashMap<>();
    this.maxRunning = maxRunning;
  }

  /**
   * Attempts to enqueue and schedule a single healing insertion for the provided block data.
   *
   * <p>This method applies the concurrency cap and consults the decision supplier; if either check
   * rejects the request, it returns {@code false} and does not schedule work. Ownership of {@code
   * data} remains with the caller on failure; on success, the queue assumes responsibility for
   * freeing the bucket via its callbacks.
   *
   * @param data the block-sized bucket to insert; must contain the correct number of bytes for a
   *     single CHK block and remain readable until the operation completes; never {@code null}.
   * @param cryptoKey the raw key material used to encrypt the block; contents are
   *     implementation-dependent and must match the algorithm parameter.
   * @param cryptoAlgorithm identifier of the encryption algorithm to use; valid values are defined
   *     by the surrounding client stack.
   * @param context the client context on which to schedule work; must be non-null and suitable for
   *     creating and running client put states.
   * @return {@code true} if the healing insertion was accepted and scheduled, {@code false} if it
   *     was declined due to capacity or decision strategy.
   */
  public boolean innerQueue(
      Bucket data, byte[] cryptoKey, byte cryptoAlgorithm, ClientContext context) {
    SingleBlockInserter sbi;
    int ctr;
    synchronized (this) {
      ctr = counter++;
      if (runningInserters.size() > maxRunning) return false;
      try {
        sbi =
            new SingleBlockInserter(
                new BlockInsertPayload(
                    data,
                    FreenetURI.EMPTY_CHK_URI,
                    (short) -1,
                    false,
                    CHKBlock.DATA_LENGTH,
                    cryptoAlgorithm,
                    cryptoKey),
                new BlockInsertParams(this, ctx, this, ctr, data, false, context),
                new BlockInsertOptions(false, realTimeFlag, true, 0),
                false);
      } catch (Exception e) {
        LOG.error("Caught trying to insert healing block", e);
        return false;
      }
      if (isHealingThisBlockSimilarToForwarding(context, sbi)) {
        runningInserters.put(data, sbi);
      }
    }
    try {
      sbi.schedule(context);
      if (LOG.isDebugEnabled()) LOG.debug("Started healing insert {} for {}", ctr, data);
      return true;
    } catch (Exception e) {
      LOG.error("Caught trying to insert healing block", e);
      return false;
    }
  }

  private boolean isHealingThisBlockSimilarToForwarding(
      ClientContext context, SingleBlockInserter sbi) {
    // ensure that we have a routing key
    sbi.tryEncode(context);
    double keyLocation = sbi.getKeyNoEncode().getNodeKey().toNormalizedDouble();
    return healingDecisionSupplier.shouldHeal(keyLocation);
  }

  /**
   * Queues a healing insertion for the provided block and frees the bucket if the request cannot be
   * scheduled.
   *
   * <p>This is the public entry point to enqueue a candidate block. When capacity is unavailable or
   * the decision supplier declines the insert, the method releases the bucket immediately to avoid
   * resource leakage.
   *
   * @param data the block-sized bucket to insert; freed by this method when not accepted; otherwise
   *     freed asynchronously by callbacks on completion.
   * @param cryptoKey the raw key material for encryption; must be compatible with the algorithm
   *     parameter and may be {@code null} when the algorithm does not require it.
   * @param cryptoAlgorithm identifier for the encryption algorithm to use; expected to match the
   *     semantics of the provided key material.
   * @param context the client context on which to schedule; must not be {@code null}.
   */
  @Override
  public void queue(Bucket data, byte[] cryptoKey, byte cryptoAlgorithm, ClientContext context) {
    if (!innerQueue(data, cryptoKey, cryptoAlgorithm, context)) data.free();
  }

  /**
   * Returns the placeholder CHK URI associated with healing operations.
   *
   * <p>Healing inserts operate on single blocks identified by CHK; this implementation uses a
   * canonical empty CHK as an identifier for the queue itself rather than a per-block value.
   *
   * @return a stable, placeholder CHK URI representing this queue rather than a specific block.
   */
  @Override
  public FreenetURI getURI() {
    return FreenetURI.EMPTY_CHK_URI;
  }

  /**
   * Reports whether the queue has finished scheduling work.
   *
   * <p>Healing queues are best-effort and open-ended; this implementation always returns {@code
   * false} and relies on cancellation to stop activity.
   *
   * @return always {@code false}, indicating the queue remains available for new work.
   */
  @Override
  public boolean isFinished() {
    return false;
  }

  /**
   * Notifies any attached clients about state changes.
   *
   * <p>Healing queues do not directly expose client notifications; this implementation performs no
   * action.
   *
   * @param context the client context provided by the framework; ignored.
   */
  @Override
  protected void innerNotifyClients(ClientContext context) {
    // Do nothing
  }

  /**
   * Callback invoked when a healing insertion completes successfully.
   *
   * <p>Removes the corresponding entry from the in-flight map, logs a diagnostic message, and frees
   * the associated bucket.
   *
   * @param state the terminal put state for the single-block insertion; expected to be a concrete
   *     single-block putter instance.
   * @param context the client context active at completion time; not modified.
   */
  @Override
  public void onSuccess(ClientPutState state, ClientContext context) {
    SingleBlockInserter sbi = (SingleBlockInserter) state;
    Bucket data = (Bucket) sbi.getToken();
    synchronized (this) {
      runningInserters.remove(data);
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Successfully inserted healing block: {} for {} ({})",
          sbi.getURINoEncode(),
          data,
          sbi.token);
    data.free();
  }

  /**
   * Callback invoked when a healing insertion fails.
   *
   * <p>Removes the corresponding entry from the in-flight map, logs a diagnostic message including
   * the failure, and frees the associated bucket.
   *
   * @param e the failure cause, as reported by the client putter, may carry detailed diagnostics.
   * @param state the put state representing the failed operation; expected to be a single-block
   *     putter instance.
   * @param context the client context active at failure time; not modified.
   */
  @Override
  public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
    SingleBlockInserter sbi = (SingleBlockInserter) state;
    Bucket data = (Bucket) sbi.getToken();
    synchronized (this) {
      runningInserters.remove(data);
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Failed to insert healing block: {} : {} for {} ({})",
          sbi.getURINoEncode(),
          e,
          data,
          sbi.token,
          e);
    data.free();
  }

  /**
   * Callback invoked during key encoding for a put operation.
   *
   * <p>Healing queues do not act on this event; the parameters are accepted and ignored.
   *
   * @param usk the client key involved in the put operation; ignored by this implementation.
   * @param state the current put state; ignored.
   * @param context the client context; ignored.
   */
  @Override
  public void onEncode(BaseClientKey usk, ClientPutState state, ClientContext context) {
    // Ignore
  }

  /**
   * Callback invoked on state transitions of a put operation.
   *
   * <p>Healing queues do not expect mid-flight transitions for the single-block path; a diagnostic
   * is logged if this occurs.
   *
   * @param oldState the previous state of the put; for diagnostics only.
   * @param newState the new state of the put; for diagnostics only.
   * @param context the client context active during the transition; not modified.
   */
  @Override
  public void onTransition(
      ClientPutState oldState, ClientPutState newState, ClientContext context) {
    // Should never happen
    LOG.error(
        "impossible: onTransition on SimpleHealingQueue from {} to {}",
        oldState,
        newState,
        new Exception("debug"));
  }

  /**
   * Callback invoked when metadata is produced by a put operation.
   *
   * <p>Healing queues perform single-block insertions and do not expect metadata; logs a diagnostic
   * when invoked.
   *
   * @param m the metadata object produced by the put; logged and otherwise ignored.
   * @param state the current put state; included in diagnostics only.
   * @param context the client context; not modified.
   */
  @Override
  public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
    // Should never happen
    LOG.error("Got metadata on SimpleHealingQueue from {}: {}", state, m, new Exception("debug"));
  }

  /**
   * Callback invoked when a block set insertion finishes.
   *
   * <p>Healing uses single-block insertions, so this event is not acted upon.
   *
   * @param state the completed state; ignored.
   * @param context the client context; ignored.
   */
  @Override
  public void onBlockSetFinished(ClientPutState state, ClientContext context) {
    // Ignore
  }

  /**
   * Callback invoked when a put becomes fetchable.
   *
   * <p>Healing does not participate in fetch-after-put flows; this is ignored.
   *
   * @param state the current put state; ignored.
   */
  @Override
  public void onFetchable(ClientPutState state) {
    // Ignore
  }

  /**
   * Callback invoked on state transitions of a get operation.
   *
   * <p>This queue focuses on put/heal flows and therefore ignores get transitions.
   *
   * @param oldState the previous get state; ignored.
   * @param newState the new get state; ignored.
   * @param context the client context; ignored.
   */
  @Override
  public void onTransition(
      ClientGetState oldState, ClientGetState newState, ClientContext context) {
    // Ignore
  }

  /**
   * Invoked to push work to the network layer.
   *
   * <p>Healing queues schedule work directly from {@code queue}; there is no additional push at
   * this stage.
   *
   * @param context the client context; ignored.
   */
  @Override
  protected void innerToNetwork(ClientContext context) {
    // Ignore
  }

  /**
   * Cancels the queue and any outstanding healing insertions.
   *
   * <p>Delegates to the superclass cancellation logic.
   *
   * @param context the client context passed by the framework; not used directly.
   */
  @Override
  public void cancel(ClientContext context) {
    super.cancel();
  }

  /**
   * A minimum number of successfully fetched blocks required by this request.
   *
   * <p>Healing insertions do not perform fetches as part of completion, so the value is zero.
   *
   * @return always {@code 0} because no fetch-based success criterion applies here.
   */
  @Override
  public int getMinSuccessFetchBlocks() {
    return 0;
  }

  /**
   * Callback invoked when metadata is provided as a bucket.
   *
   * <p>Healing queues do not expect metadata; the bucket is freed and a diagnostic is logged.
   *
   * @param meta the metadata bucket; freed immediately by this method.
   * @param state the put state that produced the metadata; logged only.
   * @param context the client context; ignored.
   */
  @Override
  public void onMetadata(Bucket meta, ClientPutState state, ClientContext context) {
    LOG.error("onMetadata() in SimpleHealingQueue - impossible");
    meta.free();
  }

  /**
   * Resumes the queue after deserialization.
   *
   * <p>This implementation does not persist or reconstruct runtime-only helpers and therefore does
   * not perform any action on resume.
   *
   * @param context the client context provided by the framework; ignored.
   */
  @Override
  public void innerOnResume(ClientContext context) {
    // Do nothing. Not persisted.
  }

  /**
   * Returns the client callback associated with this request, if any.
   *
   * <p>Healing queues do not expose a separate callback and return {@code null}.
   *
   * @return {@code null} because no explicit callback object is associated with this queue.
   */
  @Override
  protected ClientBaseCallback getCallback() {
    return null;
  }

  /**
   * Compares this queue to another object for equality.
   *
   * <p>Equality is the identity-based semantics inherited from the superclass; no additional fields
   * participate in comparison.
   *
   * @param obj the object to compare to; equality holds only when it is the same instance.
   * @return {@code true} if and only if {@code obj} is the same instance as this object.
   */
  @Override
  public boolean equals(Object obj) {
    // Preserve identity equality semantics defined by the superclass.
    return super.equals(obj);
  }

  /**
   * Returns a hash code for this queue consistent with identity equality.
   *
   * <p>The implementation delegates to the superclass and does not incorporate additional fields.
   *
   * @return a stable, identity-based hash code as defined by the superclass.
   */
  @Override
  public int hashCode() {
    // Preserve the stable, identity-based hash code from the superclass.
    return super.hashCode();
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    this.runningInserters = new HashMap<>();
  }
}
