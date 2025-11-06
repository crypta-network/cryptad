package network.crypta.client.events;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import network.crypta.client.async.ClientContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A small, in‑process implementation of {@link ClientEventProducer} that tracks a set of {@link
 * ClientEventListener}s and dispatches {@link ClientEvent}s to them.
 *
 * <p>This producer is intended for client‑layer components that need to surface progress and
 * high‑level status changes to observers (for example, UI code or logging facilities) without
 * coupling those observers to internal control flow. Callers register listeners and then invoke
 * {@link #produceEvent(ClientEvent, network.crypta.client.async.ClientContext)} whenever a notable
 * occurrence should be published. The dispatch strategy here is intentionally simple: the producer
 * takes a snapshot of the current listeners under synchronization, then iterates and invokes each
 * listener once for the provided event.
 *
 * <p><strong>Concurrency and thread‑safety:</strong> Listener registration and removal are
 * synchronized on the instance, and the field holding the listener list is safely published using a
 * {@code final} reference. Dispatch uses a snapshot to avoid concurrent modification while
 * iterating. Listener implementations must return quickly; any heavy I/O or blocking work should be
 * offloaded via the provided {@code ClientContext}.
 *
 * <ul>
 *   <li>Exceptions thrown by listeners are caught and logged; remaining listeners are still
 *       invoked.
 *   <li>Ordering of callbacks follows the registration order at the time the snapshot is taken.
 *   <li>Duplicate listener registrations are preserved and will receive duplicate callbacks.
 * </ul>
 *
 * @see ClientEvent
 * @see ClientEventListener
 * @author oskar
 */
public class SimpleEventProducer implements ClientEventProducer, Serializable {

  @Serial private static final long serialVersionUID = 1L;
  private static final Logger LOG = LoggerFactory.getLogger(SimpleEventProducer.class);

  /**
   * Registered listeners in registration order.
   *
   * <p>The reference is {@code final} to ensure safe publication; the list is mutated only while
   * holding the instance monitor. Callers never receive this instance directly; public accessors
   * return a defensive array snapshot.
   */
  @SuppressWarnings("java:S1948")
  private final ArrayList<ClientEventListener> listeners = new ArrayList<>();

  /**
   * Creates a producer with an initially empty listener set.
   *
   * <p>Use {@link #addEventListener(ClientEventListener)} or {@link
   * #addEventListeners(ClientEventListener[])} to register observers before calling {@link
   * #produceEvent(ClientEvent, network.crypta.client.async.ClientContext)}.
   */
  public SimpleEventProducer() {}

  /**
   * Creates a producer and registers each listener from the given array in order.
   *
   * <p>Registration is equivalent to calling {@link #addEventListener(ClientEventListener)} for
   * each element. The array itself may be empty, but elements must not be {@code null}. Duplicate
   * listeners are accepted and will receive duplicate callbacks.
   *
   * @param cela ordered array of initial listeners to register; must not contain {@code null}
   *     elements; duplicates are preserved and appended in the provided order.
   * @throws IllegalArgumentException if any element of {@code cela} is {@code null}.
   */
  public SimpleEventProducer(ClientEventListener[] cela) {
    this();
    for (ClientEventListener clientEventListener : cela) addEventListener(clientEventListener);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation rejects {@code null} and appends the listener to the end of the
   * registration list while holding the instance monitor.
   *
   * @param cel the listener to register; must not be {@code null}; duplicates are allowed and will
   *     result in multiple callbacks per event.
   * @throws IllegalArgumentException if {@code cel} is {@code null}.
   */
  @Override
  public synchronized void addEventListener(ClientEventListener cel) {
    if (cel != null) listeners.add(cel);
    else throw new IllegalArgumentException("Adding a null listener!");
  }

  /**
   * {@inheritDoc}
   *
   * <p>Removal is performed while holding the instance monitor. If the listener was registered
   * multiple times, only one occurrence is removed per call.
   *
   * @param cel the listener to remove; must not be {@code null}.
   * @return {@code true} if a matching listener was removed; {@code false} otherwise.
   */
  @Override
  public synchronized boolean removeEventListener(ClientEventListener cel) {
    boolean b = listeners.remove(cel);
    listeners.trimToSize();
    return b;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation takes a snapshot of current listeners under synchronization and iterates
   * over that stable array outside the synchronized block. Exceptions thrown by individual
   * listeners are caught and logged, and dispatch continues to remaining listeners.
   *
   * @param ce the event instance to deliver; must not be {@code null}.
   * @param context execution context associated with the event; may be {@code null} when no context
   *     is available to the caller.
   */
  @Override
  public void produceEvent(ClientEvent ce, ClientContext context) {
    // Events are relatively uncommon. Consistency more important than speed.
    ClientEventListener[] list;
    synchronized (this) {
      list = getEventListeners();
    }
    for (ClientEventListener cel : list) {
      try {
        cel.receive(ce, context);
      } catch (Exception ue) {
        LOG.error("Unexpected exception while delivering client event", ue);
      }
    }
  }

  /**
   * Returns a snapshot of the currently registered listeners.
   *
   * <p>The returned array is a new array whose contents reflect the registration order at the time
   * this method is called while holding the instance monitor. Modifying the returned array does not
   * affect internal state.
   *
   * @return a new array containing the registered listeners in registration order; never {@code
   *     null}, but may be empty when no listeners are registered.
   */
  public synchronized ClientEventListener[] getEventListeners() {
    ClientEventListener[] ret = new ClientEventListener[listeners.size()];
    return listeners.toArray(ret);
  }

  /**
   * Adds all listeners in the provided array in order.
   *
   * <p>Each element is added by delegating to {@link #addEventListener(ClientEventListener)}. The
   * array may be empty; elements must not be {@code null}.
   *
   * @param cela array of listeners to register; elements must not be {@code null}; duplicates are
   *     accepted and preserved.
   * @throws IllegalArgumentException if any element is {@code null}.
   */
  public synchronized void addEventListeners(ClientEventListener[] cela) {
    for (ClientEventListener clientEventListener : cela) addEventListener(clientEventListener);
  }
}
