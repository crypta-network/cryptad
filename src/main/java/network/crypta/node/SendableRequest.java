package network.crypta.node;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.client.async.ClientRequestSchedulerGroup;
import network.crypta.client.async.ClientRequester;
import network.crypta.support.RandomGrabArray;
import network.crypta.support.RandomGrabArrayItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base type for a schedulable client request that can be sent immediately.
 *
 * <p>Instances are registered on a {@link ClientRequestScheduler} and participate in the request
 * selection tree (see {@link network.crypta.support.RandomGrabArray}). Subclasses typically manage
 * a set of keys to fetch or blocks to insert and expose readiness via the {@link
 * network.crypta.support.RandomGrabArrayItem} contract.
 *
 * <p>Locking and threading: Some subclasses may synchronize with external objects (for example,
 * segment or block holders). To avoid deadlocks, callers must not invoke subclass callbacks while
 * holding locks owned by {@code SendableRequest}. In particular, take outer locks last and avoid
 * calling into subclass code while holding them.
 *
 * <p>Serialization: This type is {@link Serializable}. Changing non-transient fields in
 * implementations may invalidate the on-disk state and cause downloads to restart or uploads to be
 * lost. Not all subclasses are persisted; when in doubt, prefer adding transient state and deriving
 * it at runtime.
 */
public abstract class SendableRequest implements RandomGrabArrayItem, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(SendableRequest.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Pre-computed identity-based hash used by containers.
   *
   * <p>Values are derived from {@link Object#hashCode()} at construction time and remain stable for
   * the lifetime of the instance, ensuring consistent behavior when stored in hashed collections.
   * The value is never {@code 0} unless the object was deactivated in a persistence layer that
   * restores the field to zero.
   */
  private final int hashCode;

  protected final boolean realTimeFlag;

  // Intentionally empty: no static initialization required.

  /**
   * Creates a new request.
   *
   * @param persistent whether the request is persisted across restarts
   * @param realTimeFlag whether the request is treated as real-time (scheduler-specific semantics)
   */
  SendableRequest(boolean persistent, boolean realTimeFlag) {
    this.persistent = persistent;
    this.realTimeFlag = realTimeFlag;
    int oid = System.identityHashCode(this);
    if (oid == 0) oid = 1;
    this.hashCode = oid;
  }

  @Serial
  private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
    stream.defaultReadObject();
    parentGrabArray = new AtomicReference<>();
  }

  /**
   * Returns the stable, pre-computed identity hash for this instance.
   *
   * <p>Equals uses identity semantics (see {@link #equals(Object)}), so the hash code only needs to
   * be consistent for the lifetime of the object, not derived from logical contents.
   */
  @Override
  public final int hashCode() {
    return hashCode;
  }

  /**
   * Compares by object identity.
   *
   * <p>This method intentionally preserves identity semantics (i.e., {@code this == obj}). It is
   * declared {@code final} to prevent subclasses from introducing content-based equality that would
   * violate scheduler and container assumptions.
   */
  @Override
  public final boolean equals(Object obj) {
    // Preserve identity semantics while satisfying the equals/hashCode contract
    return this == obj;
  }

  protected transient AtomicReference<RandomGrabArray> parentGrabArray = new AtomicReference<>();

  /** Whether this request is persisted; must remain constant after construction. */
  protected final boolean persistent;

  /**
   * Returns the priority class for scheduling.
   *
   * <p>The scheduler defines the concrete values and their meaning. Higher priority classes may be
   * considered first when selecting ready items.
   *
   * @return a scheduler-defined priority class
   */
  public abstract short getPriorityClass();

  /**
   * Chooses the next item (key or block) to send.
   *
   * <p>Implementations must not modify persisted structures here but may update in-memory cooldowns
   * or bookkeeping to avoid immediate reselection. Success and failure are reported via separate
   * callbacks on the scheduler/requester path, so this method can be called outside the persistent
   * job runner.
   *
   * @param keys a view of keys currently being fetched locally; used to avoid duplicates
   * @param context client execution context
   * @return an item to send, or {@code null} if nothing is currently eligible
   */
  public abstract SendableRequestItem chooseKey(KeysFetchingLocally keys, ClientContext context);

  /**
   * Counts all known items (keys/blocks), including those not currently eligible to send.
   *
   * <p>Items on cooldown, already in flight, or otherwise temporarily excluded are included in this
   * count.
   *
   * @param context client execution context
   * @return total number of known items
   */
  public abstract long countAllKeys(ClientContext context);

  /**
   * Counts items that are currently eligible to be sent.
   *
   * <p>Does not include items already running, on cooldown, or otherwise excluded by the scheduler.
   *
   * @param context client execution context
   * @return number of items eligible for immediate sending
   */
  public abstract long countSendableKeys(ClientContext context);

  /**
   * Returns a non-persistent sender used to drive this request.
   *
   * <p>Implementations may cache and reuse a sender instance. The sender is not persisted and must
   * be recreated after restart.
   *
   * @param context client execution context
   * @return a sender that can execute this request's items
   */
  public abstract SendableRequestSender getSender(ClientContext context);

  /**
   * Returns whether this request is finished (canceled or completed).
   *
   * <p>Finished requests no longer need to be registered with the scheduler. By contrast, an
   * "empty" request may have no queued items temporarily but can still accept new work.
   */
  public abstract boolean isCancelled();

  /**
   * Returns the owning client metadata for this request.
   *
   * <p>This is typically called on registration and when reporting errors. The value is not stored
   * on the request instance; lookups are delegated to the surrounding container/subsystem.
   */
  public abstract RequestClient getClient();

  /**
   * Returns whether this request is persisted across restarts.
   *
   * <p>The value is fixed at construction and must not change.
   */
  public final boolean persistent() {
    return persistent;
  }

  /**
   * Returns the associated high-level client request.
   *
   * <p>Implementations should cache and return the same instance for the lifetime of this {@code
   * SendableRequest}.
   */
  public abstract ClientRequester getClientRequest();

  /** Returns the parent array used by the selection tree, if tracked. */
  @Override
  public RandomGrabArray getParentGrabArray() {
    return parentGrabArray.get();
  }

  // Grab and clear the parent atomically to avoid double-unregister races.
  private RandomGrabArray grabParentGrabArray() {
    return parentGrabArray.getAndSet(null);
  }

  @Override
  public boolean knowsParentGrabArray() {
    return true;
  }

  /** Sets or clears the back-reference to the current parent selection array. */
  @Override
  public void setParentGrabArray(RandomGrabArray parent) {
    parentGrabArray.set(parent);
  }

  /**
   * Unregisters this request from the selection structures.
   *
   * <p>The removal is performed while holding the scheduler's monitor to maintain consistency with
   * the selection tree. If the request is not currently registered, a debug message is logged.
   *
   * @param context client execution context
   * @param oldPrio previous priority class; some subclasses may use this when changing priorities.
   *     A value of {@code -1} indicates the caller did not specify a previous priority.
   */
  public void unregister(ClientContext context, short oldPrio) {
    RandomGrabArray arr = grabParentGrabArray();
    if (arr != null) {
      synchronized (getScheduler(context)) {
        arr.remove(this, context);
      }
    } else {
      // Should this be a higher priority?
      if (LOG.isDebugEnabled()) LOG.debug("Cannot unregister {} : not registered", this);
    }
  }

  /** Returns the scheduler responsible for this request. */
  public abstract ClientRequestScheduler getScheduler(ClientContext context);

  /** Returns whether this request targets an SSK (used to choose a scheduler). */
  public abstract boolean isSSK();

  /** Returns whether this request performs an insert (used to choose a scheduler). */
  public abstract boolean isInsert();

  /**
   * Notifies the request of an internal error and offers a chance to requeue.
   *
   * @param t the underlying cause
   * @param sched the scheduler invoking the callback
   * @param context client execution context
   * @param persistent whether to treat the error as part of a persistent workflow
   */
  public abstract void internalError(
      Throwable t, RequestScheduler sched, ClientContext context, boolean persistent);

  /**
   * Returns whether this request is treated as real-time by the scheduler.
   *
   * <p>Real-time behavior is scheduler-defined; callers should not rely on a specific policy.
   */
  public boolean realTimeFlag() {
    return realTimeFlag;
  }

  /**
   * Attempts to reduce the wakeup time of the parent selection node.
   *
   * <p>When an earlier wakeup is possible, propagation occurs via the current {@link
   * RandomGrabArray} parent.
   *
   * @param wakeupTime candidate earlier wakeup time in milliseconds since the epoch
   * @param context client execution context
   * @return {@code true} if the parent wakeup time was reduced; otherwise {@code false}
   */
  @Override
  public boolean reduceWakeupTime(long wakeupTime, ClientContext context) {
    RandomGrabArray parent = getParentGrabArray();
    if (parent == null) return false;
    return parent.reduceWakeupTime(wakeupTime, context);
  }

  /**
   * Clears any stored wakeup time on the parent selection node, forcing re-evaluation.
   *
   * @param context client execution context
   */
  @Override
  public void clearWakeupTime(ClientContext context) {
    RandomGrabArray parent = getParentGrabArray();
    if (parent == null) return;
    parent.clearWakeupTime(context);
  }

  /** Returns the scheduler group associated with the owning client request. */
  public ClientRequestSchedulerGroup getSchedulerGroup() {
    return getClientRequest().getSchedulerGroup();
  }
}
