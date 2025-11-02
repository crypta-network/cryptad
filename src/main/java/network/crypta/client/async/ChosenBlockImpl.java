package network.crypta.client.async;

import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.RequestScheduler;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableInsert;
import network.crypta.node.SendableRequest;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Concrete {@link ChosenBlock} that binds a specific {@link network.crypta.node.SendableRequest}
 * instance to a {@link RequestScheduler}. It wires low-level success and failure callbacks to the
 * originating request and performs the required scheduler bookkeeping (e.g., removing running
 * tokens and waking the starter thread) so subsequent work can proceed.
 *
 * <p>Use this implementation when a request has already selected a concrete block/token to process,
 * and the scheduler is ready to execute it. The instance captures execution options via the
 * base-class {@link Options} and remembers whether the work is {@linkplain #isPersistent()
 * persistent}. The object is effectively immutable after construction; it is safe to pass across
 * threads as callbacks schedule work back onto the appropriate {@code JobRunner} based on the
 * persistence flag.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Delegates all user-visible outcomes to the underlying request (get/insert) instance.
 *   <li>Removes in-flight tracking in the scheduler before waking the starter thread.
 *   <li>Chooses the persistent or transient job runner to queue follow-up work.
 * </ul>
 *
 * @author Matthew Toseland &lt;toad@amphibian.dyndns.org&gt; (0xE43DA450)
 * @see ChosenBlock
 * @see RequestScheduler
 */
public class ChosenBlockImpl extends ChosenBlock {
  private static final Logger LOG = LoggerFactory.getLogger(ChosenBlockImpl.class);

  /**
   * The originating {@link SendableRequest} whose sub-request (identified by {@link #token}) is
   * being executed. The reference is stable for the lifetime of this object and is not mutated by
   * this class. Implementations use it to dispatch success/failure callbacks.
   */
  public final SendableRequest request;

  /**
   * The scheduler responsible for tracking in-flight work and queuing subsequent tasks. It is used
   * to remove running inserts/fetches and to wake the starter thread after completion or failure so
   * that other waiting work can progress.
   */
  public final RequestScheduler sched;

  /**
   * Whether the block belongs to a persistent request. When {@code true}, callbacks are queued on
   * the persistent job runner; when {@code false}, the transient runner is used. This influences
   * durability and shutdown semantics but not the logical outcome of the operation itself.
   */
  public final boolean persistent;

  /**
   * Creates a new block for a selected token and keys, binding it to a concrete request and
   * scheduler. The provided flags control locality, store interaction, client cache writes, and
   * real-time behavior passed to the base {@link Options}.
   *
   * @param req the originating {@link SendableRequest}; not {@code null}; receives callbacks for
   *     success or failure.
   * @param token the scheduling token for the sub-request within the larger operation; not {@code
   *     null}.
   * @param key the low-level key to fetch/insert; may be {@code null} for request types that do not
   *     operate on a raw key.
   * @param ckey the client-layer key associated with this operation; may be {@code null} when not
   *     applicable.
   * @param localRequestOnly when {@code true}, perform work using only local resources; do not
   *     contact peers.
   * @param ignoreStore when {@code true}, bypass normal on-disk store lookups for reads where
   *     supported.
   * @param canWriteClientCache when {@code true}, allow writing client-level caches when the result
   *     is cacheable.
   * @param forkOnCacheable when {@code true}, permit sender/scheduler to fork on cacheable results
   *     to improve throughput.
   * @param realTimeFlag when {@code true}, mark work as real-time to prefer lower-latency
   *     strategies where possible.
   * @param sched the {@link RequestScheduler} coordinating this block; not {@code null}.
   * @param persistent {@code true} for persistent requests queued on the persistent runner;
   *     otherwise use the transient runner.
   */
  public ChosenBlockImpl(
      SendableRequest req,
      SendableRequestItem token,
      Key key,
      ClientKey ckey,
      boolean localRequestOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean realTimeFlag,
      RequestScheduler sched,
      boolean persistent) {
    super(
        token,
        key,
        ckey,
        new Options(
            localRequestOnly, ignoreStore, canWriteClientCache, forkOnCacheable, realTimeFlag));
    this.request = req;
    this.sched = sched;
    this.persistent = persistent;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Created {} for {} block {} for key {}",
          this,
          persistent ? "persistent" : "transient",
          token,
          key,
          new Exception("debug"));
  }

  /** {@inheritDoc} */
  @Override
  public boolean isCancelled() {
    return request.isCancelled();
  }

  /**
   * Returns whether this block is part of a persistent request. Persistent requests queue follow-up
   * work on the persistent job runner, which affects durability and shutdown handling, but does not
   * change the logical semantics of the request.
   *
   * @return {@code true} if persistent job runner semantics apply; {@code false} for transient
   *     execution.
   */
  @Override
  public boolean isPersistent() {
    return persistent;
  }

  /**
   * Handles an insert failure by delegating to the underlying {@link SendableInsert} and then
   * updating scheduler state. The token is removed from the running-insert set, and the starter
   * thread is woken so other queued work can proceed.
   *
   * <p>This method enqueues the callback onto the appropriate job runner (persistent or transient)
   * to avoid executing heavy logic on scheduling threads.
   *
   * @param e the low-level put exception describing why the insert failed; never {@code null}.
   * @param context the client execution context used by the request to finalize failure handling;
   *     not {@code null}.
   */
  @Override
  public void onFailure(final LowLevelPutException e, ClientContext context) {
    context
        .getJobRunner(persistent)
        .queueNormalOrDrop(
            context1 -> {
              try {
                ((SendableInsert) request).onFailure(e, token, context1);
              } finally {
                sched.removeRunningInsert((SendableInsert) (request), token.getKey());
                // Something might be waiting for a request to complete (e.g. if we have two
                // requests for the same key),
                // so wake the starter thread.
              }
              sched.wakeStarter();
              return false;
            });
  }

  /**
   * Handles a successful insert by notifying the underlying {@link SendableInsert} and performing
   * scheduler cleanup. The running-insert entry is removed, then the starter is woken to allow any
   * dependent or waiting work to continue.
   *
   * @param key the {@link ClientKey} produced or confirmed by the insert; may be {@code null}
   *     depending on request type.
   * @param context the client execution context made available to the request callback; not {@code
   *     null}.
   */
  @Override
  public void onInsertSuccess(final ClientKey key, ClientContext context) {
    context
        .getJobRunner(persistent)
        .queueNormalOrDrop(
            context1 -> {
              try {
                ((SendableInsert) request).onSuccess(token, key, context1);
              } finally {
                sched.removeRunningInsert((SendableInsert) (request), token.getKey());
              }
              // Something might be waiting for a request to complete (e.g. if we have two
              // requests for the same key),
              // so wake the starter thread.
              sched.wakeStarter();
              return false;
            });
  }

  /**
   * Handles a fetch failure by delegating to the underlying {@link SendableGet} and updating
   * scheduler state. The key is removed from the fetch-in-flight set and the starter thread is
   * woken to ensure progress on other work.
   *
   * @param e the low-level get exception indicating why the fetch failed; never {@code null}.
   * @param context the client execution context for the callback; not {@code null}.
   */
  @Override
  public void onFailure(final LowLevelGetException e, ClientContext context) {
    context
        .getJobRunner(persistent)
        .queueNormalOrDrop(
            context1 -> {
              try {
                ((SendableGet) request).onFailure(e, token, context1);
              } finally {
                sched.removeFetchingKey(key);
              }
              // Something might be waiting for a request to complete (e.g. if we have two
              // requests for the same key),
              // so wake the starter thread.
              sched.wakeStarter();
              return false;
            });
  }

  /**
   * Handles a successful fetch by informing the scheduler and removing the in-flight tracking for
   * the key. Any waiting work is unblocked by waking the starter thread. The underlying request is
   * considered complete for this token.
   *
   * @param context the client execution context used by the scheduler and callbacks; not {@code
   *     null}.
   */
  @Override
  public void onFetchSuccess(ClientContext context) {
    context
        .getJobRunner(persistent)
        .queueNormalOrDrop(
            context1 -> {
              try {
                sched.succeeded((SendableGet) request, false);
              } finally {
                sched.removeFetchingKey(key);
              }
              // Something might be waiting for a request to complete (e.g. if we have two
              // requests for the same key),
              // so wake the starter thread.
              sched.wakeStarter();
              return false;
            });
  }

  /**
   * Returns the request priority class used by the scheduler. The numeric value is interpreted by
   * the scheduling policy; lower numbers may represent higher priority depending on configuration.
   *
   * @return a short priority class value from the underlying {@link SendableRequest} instance.
   */
  @Override
  public short getPriority() {
    return request.getPriorityClass();
  }

  /**
   * Obtains the sender capable of executing this block under the provided context. The returned
   * sender defines whether sending blocks and performs the actual network/storage interaction.
   *
   * @param context the client execution context to use when building or selecting the sender; not
   *     {@code null}.
   * @return a non-{@code null} {@link SendableRequestSender} suitable for sending this block.
   */
  @Override
  public SendableRequestSender getSender(ClientContext context) {
    return request.getSender(context);
  }
}
