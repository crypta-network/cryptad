package network.crypta.node;

import java.io.Serial;
import network.crypta.client.InsertException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.keys.ClientKey;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract base for immediately sendable insert requests.
 *
 * <p>Instances are registered on a {@link ClientRequestScheduler}. When scheduled, the
 * implementation runs on a worker thread, performs the low‑level insert, and then calls one of the
 * callbacks: {@link #onSuccess(SendableRequestItem, ClientKey, ClientContext)} or {@link
 * #onFailure(LowLevelPutException, SendableRequestItem, ClientContext)}.
 *
 * <p>Subclasses define whether the request can interact with the client cache, whether it is
 * local‑only, and any resume behavior after persistence.
 */
public abstract class SendableInsert extends SendableRequest {
  private static final Logger LOG = LoggerFactory.getLogger(SendableInsert.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Create a new sendable insert.
   *
   * @param persistent whether the request participates in persistence across restarts
   * @param realTimeFlag whether the request uses the real‑time scheduler variant
   */
  protected SendableInsert(boolean persistent, boolean realTimeFlag) {
    super(persistent, realTimeFlag);
  }

  /**
   * Called after a successful low‑level insert.
   *
   * @param keyNum scheduler token associated with this request
   * @param key client key that identifies the inserted data
   * @param context client execution context used by the scheduler
   */
  public abstract void onSuccess(SendableRequestItem keyNum, ClientKey key, ClientContext context);

  /**
   * Called when the insert fails.
   *
   * @param e failure cause from the low‑level put path
   * @param keyNum scheduler token associated with this request
   * @param context client execution context used by the scheduler
   */
  public abstract void onFailure(
      LowLevelPutException e, SendableRequestItem keyNum, ClientContext context);

  /**
   * Handle an unexpected internal error by logging and delegating failure to the scheduler.
   *
   * @param t thrown error
   * @param sched scheduler to notify
   * @param context client execution context
   * @param persistent whether the request is persistent
   */
  @Override
  public void internalError(
      Throwable t, RequestScheduler sched, ClientContext context, boolean persistent) {
    // Avoid duplicating exception details in the message; the throwable argument carries them.
    LOG.error("Internal error in {} (details={})", this, t, t);
    sched.callFailure(
        this,
        new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, t.getMessage(), t),
        NativeThread.PriorityLevel.MAX_PRIORITY.value,
        persistent);
  }

  /**
   * Identify this request as an insert.
   *
   * @return always {@code true}
   */
  @Override
  public final boolean isInsert() {
    return true;
  }

  /**
   * Select the appropriate scheduler based on key type and real‑time mode.
   *
   * @param context client execution context used to resolve schedulers
   * @return an insert scheduler for SSK or CHK, respecting {@code realTimeFlag}
   */
  @Override
  public ClientRequestScheduler getScheduler(ClientContext context) {
    if (isSSK()) return context.getSskInsertScheduler(realTimeFlag);
    else return context.getChkInsertScheduler(realTimeFlag);
  }

  /**
   * Whether the insert may write to the client cache as part of processing.
   *
   * @return {@code true} if writing the client cache is allowed
   */
  public abstract boolean canWriteClientCache();

  /**
   * Whether this request should operate only against the local node.
   *
   * @return {@code true} if the request is local‑only
   */
  public abstract boolean localRequestOnly();

  /**
   * Whether the scheduler may fork this request when the data is cacheable.
   *
   * @return {@code true} if forking is permitted on cacheable data
   */
  public abstract boolean forkOnCacheable();

  /**
   * Called after the key has been encoded for transmission.
   *
   * @param token scheduler token associated with this request
   * @param key client key produced by the encoder
   * @param context client execution context used by the scheduler
   */
  public abstract void onEncode(SendableRequestItem token, ClientKey key, ClientContext context);

  /**
   * Whether there is any work to perform (e.g., no blocks remain to send).
   *
   * @return {@code true} if the request has no pending work
   */
  public abstract boolean isEmpty();

  /**
   * Next wakeup time used by the scheduler.
   *
   * <p>Returns {@code -1} when the request is dormant (no work to do). Returns {@code 0} to
   * indicate immediate scheduling. The {@code now} parameter is not used by this implementation.
   *
   * @param context client execution context
   * @param now current scheduler time reference
   * @return {@code -1} for dormant, or {@code 0} for immediate execution
   */
  @Override
  public long getWakeupTime(ClientContext context, long now) {
    if (isEmpty()) return -1;
    return 0;
  }

  // Ensure resume logic runs at most once per instance; not serialized.
  private transient boolean resumed = false;

  /**
   * Ensure resume logic runs once per instance and delegate to {@link
   * #innerOnResume(ClientContext)}.
   *
   * <p>This method is idempotent and thread‑safe; subsequent calls return immediately after the
   * first successful invocation.
   *
   * @param context client execution context
   * @throws InsertException if resume detects an insert‑level problem
   * @throws ResumeFailedException if state restoration fails
   */
  public final void onResume(ClientContext context) throws InsertException, ResumeFailedException {
    synchronized (this) {
      if (resumed) return;
      resumed = true;
    }
    innerOnResume(context);
  }

  /**
   * Subclass hook to restore any necessary state before scheduling continues.
   *
   * @param context client execution context
   * @throws InsertException if resume detects an insert‑level problem
   * @throws ResumeFailedException if state restoration fails
   */
  protected abstract void innerOnResume(ClientContext context)
      throws InsertException, ResumeFailedException;
}
