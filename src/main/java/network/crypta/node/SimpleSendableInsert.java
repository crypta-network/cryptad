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
 * <p>This lightweight {@link SendableInsert} variant is used internally by the node to
 * opportunistically insert one block roughly once per 200 successful requests. It is not persistent
 * and is not intended for the external client API.
 *
 * <p>Behavior:
 *
 * <ul>
 *   <li>Schedules exactly one block ({@link #block}).
 *   <li>Runs synchronously from the sender ({@code sendIsBlocking() == true}).
 *   <li>Does not retry on failure and does not emit client callbacks.
 * </ul>
 *
 * <p>Threading and state: the {@code finished} flag gates rescheduling and cancelation. Several
 * key-count and selection methods are synchronized to avoid racing with cancelation.
 */
public class SimpleSendableInsert extends SendableInsert {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleSendableInsert.class);

  @Serial private static final long serialVersionUID = 1L;

  /** The block to be inserted (CHK or SSK). Never null. */
  public final KeyBlock block;

  /** Priority class as interpreted by the scheduler. */
  public final short prioClass;

  private boolean finished;

  /** Non-persistent client used for internal bulk inserts. */
  public final RequestClient client;

  /** Scheduler responsible for this insert; must be an insert scheduler. */
  public final ClientRequestScheduler scheduler;

  /**
   * Creates a simple insert bound to the appropriate bulk put scheduler.
   *
   * @param core node client core used to resolve client and schedulers
   * @param block block to insert; must be a {@link CHKBlock} or {@link SSKBlock}
   * @param prioClass scheduler priority class
   * @throws IllegalArgumentException if {@code block} is of an unsupported type
   * @throws IllegalStateException if the resolved scheduler is not an insert scheduler
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
   * @param block block to insert (CHK or SSK)
   * @param prioClass scheduler priority class
   * @param client request client to attribute the work to
   * @param scheduler scheduler used to run this insert; must be an insert scheduler
   */
  public SimpleSendableInsert(
      KeyBlock block, short prioClass, RequestClient client, ClientRequestScheduler scheduler) {
    super(false, false);
    this.block = block;
    this.prioClass = prioClass;
    this.client = client;
    this.scheduler = scheduler;
  }

  @Override
  public void onSuccess(SendableRequestItem keyNum, ClientKey key, ClientContext context) {
    // Successful completion; no client-visible feedback.
    if (LOG.isDebugEnabled()) LOG.debug("Insert completed for {}", block);
  }

  @Override
  public void onFailure(LowLevelPutException e, SendableRequestItem keyNum, ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Insert failed for {}: {}", block, e, e);
  }

  @Override
  public short getPriorityClass() {
    return prioClass;
  }

  @Override
  public SendableRequestSender getSender(ClientContext context) {
    return new SendableRequestSender() {

      @Override
      public boolean send(
          NodeClientCore core, RequestScheduler sched, ClientContext context, ChosenBlock req) {
        // Ignore keyNum/key; this insert handles a single block.
        try {
          if (LOG.isDebugEnabled()) LOG.debug("Starting request: {}", this);
          // FIXME: bulk flag — clarify whether background inserts should set bulk=true
          core.realPut(
              block,
              req.canWriteClientCache,
              Node.FORK_ON_CACHEABLE_DEFAULT,
              Node.PREFER_INSERT_DEFAULT,
              Node.IGNORE_LOW_BACKOFF_DEFAULT,
              false);
        } catch (LowLevelPutException e) {
          onFailure(e, req.token, context);
          if (LOG.isDebugEnabled()) LOG.debug("Request failed for {}: {}", this, e, e);
          return true;
        } finally {
          finished = true;
        }
        if (LOG.isDebugEnabled()) LOG.debug("Request succeeded: {}", this);
        onSuccess(req.token, null, context);
        sched.removeRunningInsert(SimpleSendableInsert.this, req.token.getKey());
        return true;
      }

      @Override
      public boolean sendIsBlocking() {
        return true;
      }
    };
  }

  @Override
  public RequestClient getClient() {
    return client;
  }

  @Override
  public ClientRequester getClientRequest() {
    return null;
  }

  @Override
  public ClientRequestSchedulerGroup getSchedulerGroup() {
    return null;
  }

  @Override
  public boolean isCancelled() {
    return finished;
  }

  @Override
  public boolean isEmpty() {
    return finished;
  }

  /**
   * Registers this insert with the scheduler.
   *
   * <p>Resets the internal {@code finished} flag to allow scheduling again and enqueues the insert
   * with the configured {@link #scheduler}.
   */
  public void schedule() {
    finished = false; // can reschedule
    scheduler.registerInsert(this, false);
  }

  /**
   * Cancels the insert if it has not yet completed.
   *
   * <p>Marks the insert as finished and unregisters from queues using the base implementation.
   *
   * @param context request context used for unregister bookkeeping
   */
  public void cancel(ClientContext context) {
    synchronized (this) {
      if (finished) return;
      finished = true;
    }
    super.unregister(context, prioClass);
  }

  @Override
  public synchronized long countAllKeys(ClientContext context) {
    if (finished) return 0;
    return 1;
  }

  @Override
  public synchronized long countSendableKeys(ClientContext context) {
    if (finished) return 0;
    return 1;
  }

  // FIXME: share with SingleBlockInserter to avoid duplication?
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

  @Override
  public synchronized SendableRequestItem chooseKey(
      KeysFetchingLocally keys, ClientContext context) {
    MySendableRequestItem mine = new MySendableRequestItem(this);
    if (keys.hasInsert(mine)) return null;
    if (finished) return null;
    else return mine;
  }

  @Override
  public synchronized long getWakeupTime(ClientContext context, long now) {
    if (isEmpty()) return -1;
    if (scheduler.fetchingKeys().hasInsert(new MySendableRequestItem(this))) return Long.MAX_VALUE;
    return 0;
  }

  @Override
  public boolean isSSK() {
    return block instanceof SSKBlock;
  }

  @Override
  public boolean canWriteClientCache() {
    return false;
  }

  @Override
  public boolean forkOnCacheable() {
    return Node.FORK_ON_CACHEABLE_DEFAULT;
  }

  @Override
  public void onEncode(SendableRequestItem token, ClientKey key, ClientContext context) {
    // No-op; nothing to encode for this insert.
  }

  @Override
  public boolean localRequestOnly() {
    return false;
  }

  /**
   * No-op resume hook.
   *
   * <p>This insert is not persistent and does not support resuming.
   *
   * @param context request context (unused)
   * @throws InsertException never thrown by this implementation
   */
  @Override
  protected void innerOnResume(ClientContext context) throws InsertException {
    // No-op: non-persistent insert does not resume.
  }
}
