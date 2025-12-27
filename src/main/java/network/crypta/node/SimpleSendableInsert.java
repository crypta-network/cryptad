package network.crypta.node;

import java.io.Serial;
import network.crypta.client.InsertException;
import network.crypta.client.async.ChosenBlock;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.client.async.ClientRequestSchedulerGroup;
import network.crypta.client.async.ClientRequester;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientKey;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.SSKBlock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Inserts a single block without retries or client feedback.
 *
 * <p>This class provides a minimal {@link SendableInsert} implementation that schedules exactly one
 * {@link KeyBlock} on the bulk insert schedulers. It is created by the node for opportunistic
 * background inserts and is not part of the external client API or persistence layer. Instances are
 * short-lived: they are scheduled, run a single blocking send, and then mark themselves finished so
 * they are not rescheduled.
 *
 * <p>The implementation intentionally avoids retries and callbacks. Success and failure are logged
 * at debug level only, and no {@link ClientRequester} is retained. A small synchronization boundary
 * around key selection and cancellation prevents duplicate scheduling while the insert is in
 * flight. Because the insert is non-persistent, resume hooks are no-ops and scheduling metadata
 * such as the scheduler group is absent.
 *
 * <p>Responsibilities:
 *
 * <ul>
 *   <li>Select the CHK or SSK bulk insert scheduler based on the block type.
 *   <li>Expose exactly one sendable item and suppress duplicates while in flight.
 *   <li>Track completion state for cancellation and wake-up decisions.
 * </ul>
 *
 * @see SendableInsert
 * @see NodeClientCore
 */
public class SimpleSendableInsert extends SendableInsert {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleSendableInsert.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Block payload to insert.
   *
   * <p>The block is expected to be either a {@link CHKBlock} or {@link SSKBlock} and is treated as
   * immutable input for the insert. The reference is transient because this insert is
   * non-persistent and is not expected to survive serialization.
   */
  public final transient KeyBlock block;

  /**
   * Scheduler priority class for this insert.
   *
   * <p>The value is passed through unchanged to the scheduler and interpreted relative to the
   * node's configured priority bands. It has no intrinsic unit and should be treated as an opaque
   * short value.
   */
  public final short prioClass;

  /** Completion flag used to suppress rescheduling and treat the insert as empty. */
  private boolean finished;

  /**
   * Request client attribution for scheduling and accounting.
   *
   * <p>Typically this is the node's non-persistent bulk client, but callers may supply a different
   * client when constructing the insert explicitly. The reference is transient and expected to
   * remain valid only for the short lifetime of this insert.
   */
  public final transient RequestClient client;

  /**
   * Scheduler that executes this insert.
   *
   * <p>The bulk constructors choose a CHK or SSK insert scheduler based on the block type, while
   * the explicit constructor accepts any scheduler provided by the caller. The scheduler is used to
   * register, wake, and remove the insert from queues.
   */
  public final transient ClientRequestScheduler scheduler;

  /**
   * Creates a simple insert bound to the appropriate bulk put scheduler.
   *
   * <p>This constructor resolves the non-persistent bulk {@link RequestClient} from the supplied
   * {@link NodeClientCore} and selects the CHK or SSK bulk insert scheduler based on the block
   * type. It records the supplied priority class but does not register the insert; callers must
   * invoke {@link #schedule()} when they are ready to enqueue it. Unsupported block types and
   * non-insert schedulers are rejected eagerly to avoid mis-scheduling.
   *
   * @param core node client core used to resolve client and schedulers
   * @param block block payload to insert; expected CHKBlock or SSKBlock instance
   * @param prioClass scheduler priority class passed through unchanged to scheduling logic
   * @throws IllegalArgumentException if the block type is unsupported for simple inserts
   * @throws IllegalStateException if the resolved scheduler is not configured for inserts
   */
  public SimpleSendableInsert(NodeClientCore core, KeyBlock block, short prioClass) {
    super(false, false);
    this.block = block;
    this.prioClass = prioClass;
    this.client = core.getNode().getNonPersistentClientBulk();
    if (block instanceof CHKBlock) scheduler = core.getRequestStarters().chkPutSchedulerBulk;
    else if (block instanceof SSKBlock) scheduler = core.getRequestStarters().sskPutSchedulerBulk;
    else throw new IllegalArgumentException("Don't know what to do with " + block);
    if (!scheduler.isInsertScheduler())
      throw new IllegalStateException("Scheduler " + scheduler + " is not an insert scheduler!");
  }

  /**
   * Creates a simple insert with explicit client and scheduler.
   *
   * <p>This constructor stores the supplied references without additional validation. Callers are
   * responsible for providing a scheduler that can handle inserts and a client suitable for
   * attribution and accounting. The insert is not registered automatically; call {@link
   * #schedule()} to enqueue it once configuration is complete.
   *
   * @param block block payload to insert; expected CHKBlock or SSKBlock instance
   * @param prioClass scheduler priority class passed through unchanged to scheduling logic
   * @param client request client used for attribution and queue accounting
   * @param scheduler scheduler used to run the insert; should accept inserts
   */
  public SimpleSendableInsert(
      KeyBlock block, short prioClass, RequestClient client, ClientRequestScheduler scheduler) {
    super(false, false);
    this.block = block;
    this.prioClass = prioClass;
    this.client = client;
    this.scheduler = scheduler;
  }

  /**
   * Handles a successful completion of the single insert attempt.
   *
   * <p>This callback is invoked by the sender after {@link NodeClientCore#realPut} returns without
   * throwing. It does not notify any {@link ClientRequester} and performs no state changes; the
   * finished flag is managed by the sender. The only observable effect is a debug log entry, making
   * this method safe to call multiple times but ordinarily invoked once per insert.
   *
   * @param keyNum token identifying the scheduled item; used for logging only
   * @param key client key associated with the insert; ignored and may be null
   * @param context request context for the execution; not used by this implementation
   */
  @Override
  public void onSuccess(SendableRequestItem keyNum, ClientKey key, ClientContext context) {
    // Successful completion; no client-visible feedback.
    if (LOG.isDebugEnabled()) LOG.debug("Insert completed for {}", block);
  }

  /**
   * Handles a failed insert attempt.
   *
   * <p>This callback is invoked when {@link NodeClientCore#realPut} throws a {@link
   * LowLevelPutException}. The method logs the failure at debug level and does not request retries
   * or propagate the exception. Completion state is still finalized by the sender, so this method
   * focuses solely on recording the outcome for diagnostics.
   *
   * @param e failure describing why the low-level insert did not succeed
   * @param keyNum token identifying the scheduled item; used for logging only
   * @param context request context for the execution; not used by this implementation
   */
  @Override
  public void onFailure(LowLevelPutException e, SendableRequestItem keyNum, ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Insert failed for {}: {}", block, e, e);
  }

  /**
   * Returns the scheduler priority class for this insert.
   *
   * <p>The value is supplied at construction time and is passed through unchanged to the scheduler.
   * It is used for queue selection and accounting and does not depend on the request context. This
   * method is side-effect free and may be called at any time, including after cancellation.
   *
   * @return scheduler priority class associated with this insert instance
   */
  @Override
  public short getPriorityClass() {
    return prioClass;
  }

  /**
   * Creates a sender that performs the single blocking insert attempt.
   *
   * <p>The returned {@link SendableRequestSender} issues {@link NodeClientCore#realPut} for the
   * configured block, records completion by setting {@code finished}, and forwards success or
   * failure to {@link #onSuccess} or {@link #onFailure}. On success, it also removes the running
   * insert from the scheduler. The sender reports blocking behavior and is intended for one-shot
   * use by the scheduler.
   *
   * @param context request context for sender creation; not used directly
   * @return sender instance bound to this insert; always non-null
   */
  @Override
  public SendableRequestSender getSender(ClientContext context) {
    return new SendableRequestSender() {

      @Override
      public boolean send(
          NodeClientCore core, RequestScheduler sched, ClientContext context, ChosenBlock req) {
        // Ignore keyNum/key; this insert handles a single block.
        boolean succeeded = false;
        try {
          if (LOG.isDebugEnabled()) LOG.debug("Starting request: {}", this);
          // Background inserts run as bulk (realTimeFlag=false).
          core.realPut(
              block,
              req.canWriteClientCache,
              Node.FORK_ON_CACHEABLE_DEFAULT,
              Node.PREFER_INSERT_DEFAULT,
              Node.IGNORE_LOW_BACKOFF_DEFAULT,
              false);
          succeeded = true;
        } catch (LowLevelPutException e) {
          onFailure(e, req.token, context);
          if (LOG.isDebugEnabled()) LOG.debug("Request failed for {}: {}", this, e, e);
        } finally {
          finished = true;
        }
        if (succeeded) {
          if (LOG.isDebugEnabled()) LOG.debug("Request succeeded: {}", this);
          onSuccess(req.token, null, context);
          sched.removeRunningInsert(SimpleSendableInsert.this, req.token.getKey());
        }
        return true;
      }

      @Override
      public boolean sendIsBlocking() {
        return true;
      }
    };
  }

  /**
   * Returns the client attribution for this insert.
   *
   * <p>The scheduler uses the client for accounting and queue selection. This method returns the
   * reference provided at construction time without modification and does not perform null checks.
   * Callers should treat a null result as an unsupported configuration rather than a valid client.
   *
   * @return request client used for attribution, or null if misconfigured
   */
  @Override
  public RequestClient getClient() {
    return client;
  }

  /**
   * Indicates that this insert has no associated client requester.
   *
   * <p>SimpleSendableInsert is an internal background operation and does not maintain a {@link
   * ClientRequester} for callbacks or persistence. Returning {@code null} communicates to scheduler
   * logic that there is no client-visible request to update. This keeps the insert lightweight and
   * avoids any persistence bookkeeping tied to client identifiers.
   *
   * @return {@code null} because no client requester is associated with this insert
   */
  @Override
  public ClientRequester getClientRequest() {
    return null;
  }

  /**
   * Indicates that this insert does not belong to a scheduler group.
   *
   * <p>The bulk insert path does not define a {@link ClientRequestSchedulerGroup} for this
   * operation. Returning {@code null} keeps scheduling metadata minimal and reflects that the
   * insert is not part of a client-managed group or persistence scope. Grouping is handled
   * elsewhere, so this insert remains ungrouped for its lifetime.
   *
   * @return {@code null} because no scheduler group is assigned here
   */
  @Override
  public ClientRequestSchedulerGroup getSchedulerGroup() {
    return null;
  }

  /**
   * Reports whether the insert has completed or been canceled.
   *
   * <p>The finished flag is set when the sender completes or when {@link #cancel(ClientContext)} is
   * invoked. This method provides a lightweight status check used by scheduler logic to decide
   * whether any work remains. It does not synchronize, so it reflects the most recently observed
   * flag value.
   *
   * @return {@code true} when the insert is finished; {@code false} otherwise
   */
  @Override
  public boolean isCancelled() {
    return finished;
  }

  /**
   * Treats a completed insert as empty for scheduling purposes.
   *
   * <p>This method delegates to {@link #isCancelled()} so that completion and cancellation are
   * handled consistently by the scheduler. A finished insert yields no keys and should not be
   * rescheduled. The method is side-effect free and returns immediately. It does not modify
   * scheduler state.
   *
   * @return {@code true} when there is no remaining work left
   */
  @Override
  public boolean isEmpty() {
    return isCancelled();
  }

  /**
   * Registers this insert with its scheduler for execution.
   *
   * <p>The method clears the finished flag to permit scheduling again and then registers the insert
   * with the configured scheduler as a bulk insert. It does not perform the network operation
   * itself and returns immediately after enqueueing. Callers should only invoke this when they
   * intend to schedule the single-block insert.
   */
  public void schedule() {
    finished = false; // can reschedule
    scheduler.registerInsert(this, false);
  }

  /**
   * Cancels the insert if it has not yet completed.
   *
   * <p>The method synchronizes to avoid races with scheduling and sets the finished flag before
   * delegating to {@link SendableInsert#unregister}. If the insert is already finished, the call is
   * a no-op. No additional cancellation logic is performed beyond unregistering from queues.
   *
   * @param context request context used for unregister bookkeeping and metrics
   */
  public void cancel(ClientContext context) {
    synchronized (this) {
      if (finished) return;
      finished = true;
    }
    super.unregister(context, prioClass);
  }

  /**
   * Returns the total number of keys represented by this insert.
   *
   * <p>This insert represents at most one key. If it is finished, the method returns {@code 0};
   * otherwise it returns {@code 1}. The method is synchronized to keep the count consistent with
   * cancellation and selection logic and has no side effects. This is a constant-time check.
   *
   * @param context request context used for counting decisions; unused here
   * @return number of keys represented by this insert, either zero or one
   */
  @Override
  public synchronized long countAllKeys(ClientContext context) {
    if (finished) return 0;
    return 1;
  }

  /**
   * Returns the number of currently sendable keys.
   *
   * <p>Because this insert has exactly one key when active, the sendable count is the same as the
   * total count. This method delegates to {@link #countAllKeys(ClientContext)} and remains
   * synchronized for consistency with cancellation state. No additional filtering is applied, and
   * the result is either {@code 0} or {@code 1}.
   *
   * @param context request context used for counting decisions; unused here
   * @return number of keys currently sendable for this insert
   */
  @Override
  public synchronized long countSendableKeys(ClientContext context) {
    return countAllKeys(context);
  }

  private static class MySendableRequestItem
      implements SendableRequestItem, SendableRequestItemKey {

    final SimpleSendableInsert parent;

    public MySendableRequestItem(SimpleSendableInsert parent) {
      this.parent = parent;
    }

    @Override
    public void dump() {
      // No-op for this single-block insert type.
    }

    @Override
    public SendableRequestItemKey getKey() {
      return this;
    }

    @Override
    public boolean equals(Object o) {
      if (o instanceof MySendableRequestItem item) {
        return item.parent == parent;
      } else return false;
    }

    @Override
    public int hashCode() {
      return parent.hashCode();
    }
  }

  /**
   * Chooses the single request item when it is eligible to send.
   *
   * <p>The method constructs a lightweight {@link SendableRequestItem} wrapper and checks the
   * {@link KeysFetchingLocally} tracker to ensure the insert is not already in flight. If the
   * insert is finished or already present in the tracker, it returns {@code null} to indicate that
   * no key should be scheduled. Otherwise, it returns the new request item. The method is
   * synchronized to coordinate with cancellation.
   *
   * @param keys tracker of locally fetching keys used to avoid duplicates
   * @param context request context provided by the scheduler; unused here
   * @return the single request item, or {@code null} when none is available
   */
  @Override
  public synchronized SendableRequestItem chooseKey(
      KeysFetchingLocally keys, ClientContext context) {
    MySendableRequestItem mine = new MySendableRequestItem(this);
    if (keys.hasInsert(mine)) return null;
    if (finished) return null;
    else return mine;
  }

  /**
   * Computes the scheduler wake-up time for this insert.
   *
   * <p>If the insert is empty, returns {@code -1} to indicate no wake-up is required. If the
   * scheduler is already fetching this insert, returns {@link Long#MAX_VALUE} to defer any further
   * wake-ups. Otherwise, returns {@code 0} to request immediate scheduling. The {@code now}
   * parameter is ignored because the policy depends only on in-flight state.
   *
   * @param context request context used by the scheduler; unused here
   * @param now current time provided by the scheduler; ignored by this implementation
   * @return wake-up time indicator used by the scheduler for rescheduling
   */
  @Override
  public synchronized long getWakeupTime(ClientContext context, long now) {
    if (isEmpty()) return -1;
    if (scheduler.fetchingKeys().hasInsert(new MySendableRequestItem(this))) return Long.MAX_VALUE;
    return 0;
  }

  /**
   * Reports whether the block represents an SSK insert.
   *
   * <p>This is a simple type check against {@link SSKBlock} and is used by scheduler logic to
   * select SSK-specific behavior. It has no side effects and does not depend on context. The result
   * reflects only the block supplied at construction time here.
   *
   * @return {@code true} when the block is an {@link SSKBlock} instance
   */
  @Override
  public boolean isSSK() {
    return block instanceof SSKBlock;
  }

  /**
   * Indicates whether this insert may write to the client cache.
   *
   * <p>SimpleSendableInsert performs internal background inserts and never writes to the client
   * cache. Returning {@code false} keeps the insert isolated from client-visible caching behavior.
   * This matches the non-persistent nature of the insert and avoids creating cache entries for
   * opportunistic traffic by design.
   *
   * @return {@code false} because client cache writes are not permitted
   */
  @Override
  public boolean canWriteClientCache() {
    return false;
  }

  /**
   * Returns the fork-on-cacheable policy for this insert.
   *
   * <p>The policy is delegated to {@link Node#FORK_ON_CACHEABLE_DEFAULT}, matching the node's
   * default behavior for background inserts. The method is side-effect free and does not inspect
   * the request context. This keeps simple inserts aligned with the node-wide cacheable fork policy
   * for background traffic.
   *
   * @return fork-on-cacheable setting used by the node defaults policy
   */
  @Override
  public boolean forkOnCacheable() {
    return Node.FORK_ON_CACHEABLE_DEFAULT;
  }

  /**
   * Receives encode notifications for scheduled items.
   *
   * <p>This implementation performs no work because the insert already holds a prepared {@link
   * KeyBlock}. The method exists to satisfy the superclass contract and to allow the scheduler to
   * call it uniformly. All parameters are ignored and no side effects occur here.
   *
   * @param token request item representing the insert; ignored by this method
   * @param key client key associated with the insert; ignored and may be null
   * @param context request context for the execution; not used by this implementation
   */
  @Override
  public void onEncode(SendableRequestItem token, ClientKey key, ClientContext context) {
    // No-op; nothing to encode for this insert.
  }

  /**
   * Indicates whether the insert must stay on the local node.
   *
   * <p>Returns {@code false} so the scheduler may route the insert normally. The value is constant
   * for this implementation and does not depend on request state. This keeps the behavior
   * consistent with bulk background inserts and allows normal routing decisions by default.
   *
   * @return {@code false} to allow normal routing beyond the local node
   */
  @Override
  public boolean localRequestOnly() {
    return false;
  }

  /**
   * No-op resume hook for non-persistent inserts.
   *
   * <p>This insert is not persisted, so there is no state to reconstruct after a restart. The
   * method remains to satisfy the {@link SendableInsert} contract and intentionally performs no
   * work. It never throws {@link InsertException}, but the signature is preserved for compatibility
   * with the base class.
   *
   * @param context request context passed by the scheduler; unused here
   * @throws InsertException never thrown by this implementation method
   */
  @Override
  protected void innerOnResume(ClientContext context) throws InsertException {
    // No-op: non-persistent insert does not resume.
  }
}
