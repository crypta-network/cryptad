package network.crypta.node;

import java.io.Serial;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetState;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.client.async.ClientRequester;
import network.crypta.client.async.WantsCooldownCallback;
import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Low-level GET request that can be scheduled and sent immediately.
 *
 * <p>This type exposes the minimal API needed by the request scheduler to fetch a key from the
 * network. Concrete subclasses supply the {@link #getKey(SendableRequestItem)} to fetch, the {@link
 * #getContext()} used for policy and limits, and implement failure handling.
 *
 * <p>Warning: Changing non-{@code transient} fields of serializable classes can cause in-progress
 * downloads to restart or uploads to be lost. Some subclasses are persisted; take care when
 * evolving their state.
 *
 * @see SendableRequest
 */
public abstract class SendableGet extends BaseSendableGet {
  private static final Logger LOG = LoggerFactory.getLogger(SendableGet.class);

  @Serial private static final long serialVersionUID = 1L;

  /** Owning requester that created this instance; used by schedulers and callbacks. */
  public final ClientRequester parent;

  /**
   * Returns the client-level key to fetch for the given token.
   *
   * @param token request item representing the specific sub-task or block
   * @return the key to fetch for {@code token}, or {@code null} if none applies
   */
  public abstract ClientKey getKey(SendableRequestItem token);

  /**
   * Derives the node-level key corresponding to {@link #getKey(SendableRequestItem)}.
   *
   * <p>The returned key is suitable for datastore checks and routing decisions.
   *
   * @param token request item used to determine the key
   * @return the node-level key, or {@code null} if no client key is available
   */
  @Override
  public Key getNodeKey(SendableRequestItem token) {
    ClientKey key = getKey(token);
    if (key == null) return null;
    return key.getNodeKey(true);
  }

  /**
   * Returns the set of keys this request is interested in for datastore probing and scheduling.
   *
   * <p>This lives on {@code SendableGet} rather than a listener so the scheduler can process the
   * request in smaller, independent chunks.
   *
   * @return an array of keys to check against the datastore
   */
  public abstract Key[] listKeys();

  /**
   * Returns the fetch context that carries policy, limits, and other settings.
   *
   * @return fetch context for this request
   */
  public abstract FetchContext getContext();

  /**
   * Handles a failure reported by the low-level fetch layer.
   *
   * @param e error describing why the fetch failed
   * @param token request item that failed
   * @param context client runtime context
   */
  public abstract void onFailure(
      LowLevelGetException e, SendableRequestItem token, ClientContext context);

  // Implementation

  /**
   * Creates a new sendable GET request.
   *
   * @param parent owning requester that coordinates this request
   * @param realTimeFlag whether the request runs in real-time mode
   */
  protected SendableGet(ClientRequester parent, boolean realTimeFlag) {
    super(parent.persistent(), realTimeFlag);
    this.parent = parent;
  }

  static final SendableGetRequestSender sender = new SendableGetRequestSender();

  /**
   * Returns the shared sender implementation used to execute GET requests.
   *
   * @param context client runtime context
   * @return a sender capable of sending this request type
   */
  @Override
  public SendableRequestSender getSender(ClientContext context) {
    return sender;
  }

  /**
   * Selects the appropriate scheduler for this request based on key type and urgency.
   *
   * @param context client runtime context
   * @return scheduler for CHK/SSK GETs in real-time or bulk lanes
   */
  @Override
  public ClientRequestScheduler getScheduler(ClientContext context) {
    if (isSSK()) return context.getSskFetchScheduler(realTimeFlag);
    else return context.getChkFetchScheduler(realTimeFlag);
  }

  /**
   * Returns the time at which the given token will leave the cooldown queue.
   *
   * <p>The value uses the scheduler's time base and is suitable for comparison with wakeup times
   * passed to {@link #reduceWakeupTime(long, ClientContext)}.
   *
   * @param token request item whose cooldown wakeup is being queried
   * @param context client runtime context
   * @return the cooldown wakeup time for {@code token}
   */
  @SuppressWarnings("unused")
  public abstract long getCooldownWakeup(SendableRequestItem token, ClientContext context);

  /**
   * Reports an unexpected internal error affecting this request and schedules a failure callback.
   *
   * @param t thrown error
   * @param sched scheduler used to dispatch the failure
   * @param context client runtime context
   * @param persistent whether this request is persistent
   */
  @Override
  public void internalError(
      final Throwable t, final RequestScheduler sched, ClientContext context, boolean persistent) {
    LOG.error("Internal error on {} : {}", this, t, t);
    sched.callFailure(
        this,
        new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR, t.getMessage(), t),
        NativeThread.PriorityLevel.MAX_PRIORITY.value,
        persistent);
  }

  /**
   * Indicates this is not an insert operation.
   *
   * @return always {@code false}
   */
  @Override
  public final boolean isInsert() {
    return false;
  }

  /**
   * Unregisters this request from internal trackers when it is no longer scheduled.
   *
   * @param context client runtime context
   * @param oldPrio previous priority class; {@code -1} means use the current class
   */
  @Override
  public void unregister(ClientContext context, short oldPrio) {
    super.unregister(context, oldPrio);
    context.checker.removeRequest(
        this, persistent, context, oldPrio == -1 ? getPriorityClass() : oldPrio);
  }

  /**
   * Translates a low-level fetch error into a client-facing {@link FetchException}.
   *
   * @param e low-level exception raised during a GET
   * @return mapped client exception describing the failure mode
   */
  public static FetchException translateException(LowLevelGetException e) {
    return switch (e.code) {
      case LowLevelGetException.DATA_NOT_FOUND, LowLevelGetException.DATA_NOT_FOUND_IN_STORE ->
          new FetchException(FetchExceptionMode.DATA_NOT_FOUND);
      case LowLevelGetException.RECENTLY_FAILED ->
          new FetchException(FetchExceptionMode.RECENTLY_FAILED);
      case LowLevelGetException.DECODE_FAILED, LowLevelGetException.VERIFY_FAILED ->
          new FetchException(FetchExceptionMode.BLOCK_DECODE_ERROR);
      case LowLevelGetException.INTERNAL_ERROR ->
          new FetchException(FetchExceptionMode.INTERNAL_ERROR);
      case LowLevelGetException.REJECTED_OVERLOAD ->
          new FetchException(FetchExceptionMode.REJECTED_OVERLOAD);
      case LowLevelGetException.ROUTE_NOT_FOUND ->
          new FetchException(FetchExceptionMode.ROUTE_NOT_FOUND);
      case LowLevelGetException.TRANSFER_FAILED ->
          new FetchException(FetchExceptionMode.TRANSFER_FAILED);
      case LowLevelGetException.CANCELLED -> new FetchException(FetchExceptionMode.CANCELLED);
      default -> {
        LOG.error("Unknown LowLevelGetException code: {}", e.code);
        yield new FetchException(
            FetchExceptionMode.INTERNAL_ERROR, "Unknown error code: " + e.code);
      }
    };
  }

  /**
   * Reduces the next wakeup time for this request and notifies cooldown listeners if any.
   *
   * @param wakeupTime new wakeup time in the scheduler's time base
   * @param context client runtime context
   * @return {@code true} if the wakeup time was reduced
   */
  @Override
  public boolean reduceWakeupTime(final long wakeupTime, ClientContext context) {
    boolean ret = super.reduceWakeupTime(wakeupTime, context);
    if (this.parent instanceof WantsCooldownCallback) {
      context
          .getJobRunner(persistent)
          .queueNormalOrDrop(
              context1 -> {
                ((WantsCooldownCallback) parent)
                    .enterCooldown(getClientGetState(), wakeupTime, context1);
                return false;
              });
    }
    return ret;
  }

  /**
   * Clears any pending wakeup time and notifies cooldown listeners if present.
   *
   * @param context client runtime context
   */
  @Override
  public void clearWakeupTime(ClientContext context) {
    super.clearWakeupTime(context);
    if (this.parent instanceof WantsCooldownCallback) {
      context
          .getJobRunner(persistent)
          .queueNormalOrDrop(
              context1 -> {
                ((WantsCooldownCallback) parent).clearCooldown(getClientGetState());
                return false;
              });
    }
  }

  /**
   * Returns the client-visible state object associated with this GET.
   *
   * @return state used for bridging to callbacks and UI
   */
  protected abstract ClientGetState getClientGetState();
}
