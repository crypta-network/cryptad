package network.crypta.client.async;

import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestScheduler;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestSender;

/**
 * Represents a single, already-selected unit of work in the client request pipeline. A {@code
 * ChosenBlock} bundles the scheduling token and any request-specific keys together with the
 * execution options required by the {@link RequestScheduler} and the {@link SendableRequestSender}
 * to actually perform the operation. Implementations provide a {@linkplain
 * #getSender(ClientContext) sender}, drive sending via {@link #send(NodeClientCore,
 * RequestScheduler)}, and receive success and failure callbacks.
 *
 * <p>Callbacks typically run off-thread. They are expected to trigger the higher-level callbacks
 * owned by the request (for example, on a sendable get/put) and to perform any associated
 * bookkeeping such as removing keys from local in-flight tracking. The {@linkplain #token token} is
 * never {@code null} and uniquely identifies the sub-request inside a larger multipart operation.
 * The {@linkplain #key key} and {@linkplain #ckey client key} may be {@code null} depending on the
 * request type.
 *
 * <p>Threading and state: instances are effectively immutable after construction. The only mutable
 * state is the internal flag that records whether the last {@link #send(NodeClientCore,
 * RequestScheduler) send} blocks. Implementations should document any additional concurrency
 * expectations. Typical usage is:
 *
 * <ul>
 *   <li>Obtain a {@link SendableRequestSender} via {@link #getSender(ClientContext)}.
 *   <li>Invoke {@link #send(NodeClientCore, RequestScheduler)} to enqueue or perform the work.
 *   <li>Handle {@link #onFetchSuccess(ClientContext)} or the {@code onFailure(...)} callbacks.
 *   <li>Use {@link #getPriority()} and {@link #isPersistent()} to inform scheduling decisions.
 * </ul>
 *
 * @author Matthew Toseland &lt;toad@amphibian.dyndns.org&gt; (0xE43DA450)
 * @see SendableRequestItem
 * @see SendableRequestSender
 * @see RequestScheduler
 * @see NodeClientCore
 */
public abstract class ChosenBlock {

  /**
   * Options controlling request execution semantics.
   *
   * <p>The flags influence how a request is evaluated against local storage and whether certain
   * caches are consulted or written. The precise interpretation is defined by the concrete
   * request/sender implementation and storage layer.
   *
   * @param localRequestOnly when {@code true}, restricts work to local resources only; do not
   *     contact peers.
   * @param ignoreStore when {@code true}, bypass normal on-disk store lookups for reads where
   *     supported.
   * @param canWriteClientCache when {@code true}, allow writing client-level caches if the result
   *     is cacheable for this request.
   * @param forkOnCacheable when {@code true}, allow the scheduler/sender to fork the work when the
   *     result is cacheable, e.g., to improve throughput.
   * @param realTimeFlag when {@code true}, mark the work as real-time, enabling lower latency
   *     choices where applicable.
   */
  public record Options(
      boolean localRequestOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean realTimeFlag) {}

  /**
   * The token indicating the key within the request to be fetched/inserted. Meaning is entirely
   * defined by the request.
   */
  public final SendableRequestItem token;

  /**
   * The low-level key to be fetched or inserted. It may be {@code null} for request types that do
   * not operate on a raw {@link Key}; see the concrete request for details.
   */
  public final Key key;

  /**
   * The client-layer key associated with the operation. It may be {@code null} for request types
   * that do not use a {@link ClientKey} abstraction.
   */
  public final ClientKey ckey;

  /**
   * If {@code true}, executes without contacting peers and confines itself to local resources only
   * (e.g., caches and stores). Exact behavior is request-specific.
   */
  public final boolean localRequestOnly;

  /**
   * If {@code true}, bypasses normal store lookups during reads where that behavior is supported by
   * the underlying sender/storage implementation.
   */
  public final boolean ignoreStore;

  /**
   * If {@code true}, allows the client cache to be populated when the result is considered
   * cacheable for this request type.
   */
  public final boolean canWriteClientCache;

  /**
   * If {@code true}, permits forking behavior on cacheable results in order to improve throughput
   * or responsiveness. The concrete sender decides when and how to fork.
   */
  public final boolean forkOnCacheable;

  /**
   * If {@code true}, marks the work as real-time. Scheduling and timeouts may prefer lower latency
   * strategies over maximum throughput.
   */
  public final boolean realTimeFlag;

  /**
   * Creates a new {@code ChosenBlock} with the given scheduling token, optional keys, and execution
   * options.
   *
   * <p>The {@code token} must be non-{@code null}. The {@code key} and {@code ckey} may be {@code
   * null} for request types that do not operate with those abstractions. All options are copied as
   * value semantics from the provided {@link Options} record.
   *
   * @param token the non-{@code null} sub-request token used by the scheduler and sender.
   * @param key an optional low-level {@link Key} for the operation; may be {@code null}.
   * @param ckey an optional client-layer {@link ClientKey}; may be {@code null} depending on type.
   * @param options execution options affecting local-only behavior, cache usage, and real-time
   *     hints; must be non-{@code null}.
   * @throws NullPointerException if {@code token} is {@code null}.
   */
  protected ChosenBlock(SendableRequestItem token, Key key, ClientKey ckey, Options options) {
    this.token = requireToken(token);
    this.key = key;
    this.ckey = ckey;
    this.localRequestOnly = options.localRequestOnly();
    this.ignoreStore = options.ignoreStore();
    this.canWriteClientCache = options.canWriteClientCache();
    this.forkOnCacheable = options.forkOnCacheable();
    this.realTimeFlag = options.realTimeFlag();
  }

  private static SendableRequestItem requireToken(SendableRequestItem token) {
    if (token == null) {
      throw new NullPointerException();
    }
    return token;
  }

  /**
   * Indicates whether the underlying request persists across node restarts or failure recovery.
   *
   * @return {@code true} if the request is persisted by the client layer; otherwise {@code false}.
   */
  public abstract boolean isPersistent();

  /**
   * Indicates whether this block has been canceled and will not be sent or re-sent by the
   * scheduler.
   *
   * @return {@code true} if the block is canceled and should not proceed; otherwise {@code false}.
   */
  public abstract boolean isCancelled();

  /**
   * Called when an insert operation fails at a low level.
   *
   * <p>Implementations should translate or forward the error to higher-level callbacks owned by the
   * request, and perform any necessary local clean-up. This method is invoked off-thread relative
   * to the scheduler loop.
   *
   * @param e the low-level put exception describing the cause and any diagnostic information.
   * @param context the client execution context associated with the scheduler and request flow.
   */
  public abstract void onFailure(LowLevelPutException e, ClientContext context);

  /**
   * Called when an insert operation succeeds.
   *
   * <p>Implementations should trigger higher-level success callbacks and update any relevant
   * caches/stores according to the configured {@link Options}.
   *
   * @param key the client-level key that was successfully inserted; never {@code null} for insert
   *     paths.
   * @param context the client execution context associated with the scheduler and request flow.
   */
  public abstract void onInsertSuccess(ClientKey key, ClientContext context);

  /**
   * Called when a fetch operation fails at a low level.
   *
   * <p>Implementations should translate or forward the error to higher-level callbacks owned by the
   * request, and perform any necessary local clean-up. This method is invoked off-thread relative
   * to the scheduler loop.
   *
   * @param e the low-level get exception describing the cause and any diagnostic information.
   * @param context the client execution context associated with the scheduler and request flow.
   */
  public abstract void onFailure(LowLevelGetException e, ClientContext context);

  /**
   * The actual data delivery goes through CRS.tripPendingKey(). This is just a notification for
   * bookkeeping purposes. We call the scheduler to tell it that the request succeeded, so that it
   * can be rescheduled soon for more requests.
   *
   * <p>Implementations may use this to update caches or to schedule follow-on work. It is invoked
   * off-thread relative to the scheduler loop.
   *
   * @param context the client execution context associated with the scheduler and request flow.
   */
  public abstract void onFetchSuccess(ClientContext context);

  /**
   * Returns the scheduling priority for this block. Higher values typically indicate greater
   * urgency; the exact scale and policy are determined by the scheduler.
   *
   * @return a short integer representing the scheduler priority for this block.
   */
  public abstract short getPriority();

  private boolean sendIsBlocking;

  /**
   * Sends this block using the sender obtained from {@link #getSender(ClientContext)}.
   *
   * <p>The method acquires the current {@link ClientContext} from the provided scheduler,
   * determines whether the underlying sender is blocking, records that state, and then delegates
   * the actual work to the sender. The return value reflects whether the sender accepted the work
   * immediately or deferred it.
   *
   * <pre>{@code
   * // Example: initiate sending inside a scheduler decision
   * boolean accepted = block.send(core, scheduler);
   * if (block.sendIsBlocking()) { // adjust scheduling if necessary }
   * }</pre>
   *
   * @param core the node client core used to access runtime services and network plumbing.
   * @param sched the request scheduler orchestrating priorities and execution flow.
   * @return {@code true} if the sender initiated or queued the work successfully; {@code false}
   *     otherwise.
   */
  public boolean send(NodeClientCore core, RequestScheduler sched) {
    ClientContext context = sched.getContext();
    SendableRequestSender sender = getSender(context);
    sendIsBlocking = sender.sendIsBlocking();
    return sender.send(core, sched, context, this);
  }

  /**
   * Returns the sender responsible for executing this block under the given context.
   *
   * @param context the client execution context to use when creating or configuring the sender.
   * @return a non-{@code null} sender that knows how to perform this block's work.
   */
  public abstract SendableRequestSender getSender(ClientContext context);

  /**
   * Invoked when the scheduler discards this block (for example, due to cancellation or queue
   * management). The default implementation delegates to {@link SendableRequestItem#dump()} on the
   * {@link #token} to release any associated resources.
   */
  public void onDumped() {
    token.dump();
  }

  /**
   * Indicates whether the last call to {@link #send(NodeClientCore, RequestScheduler)} used a
   * blocking sender. Call this accessor only after {@code send(...)} has been invoked.
   *
   * @return {@code true} if the underlying sender reports that sending blocks the caller; otherwise
   *     {@code false}.
   */
  @SuppressWarnings("unused")
  public boolean sendIsBlocking() {
    return sendIsBlocking;
  }
}
