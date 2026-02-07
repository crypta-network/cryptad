package com.onionnetworks.util;

import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.EventListener;
import java.util.EventObject;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Dispatches {@link java.util.EventObject} instances to registered {@link EventListener}s by
 * reflectively invoking a named method on each listener. Uses an internal queue and background
 * thread to process events asynchronously.
 *
 * <p>The dispatcher maintains a daemon thread that repeatedly removes queued {@code EventObject}
 * instances, looks up listeners that registered interest in the originating event source and the
 * supplied method name, and invokes that method with the event as its sole argument. Listener look-
 * * ups and queue mutations are synchronized in the dispatcher instance, allowing multiple producer
 * threads to submit events while the consumer thread drains the queue. Method lookups are cached to
 * avoid repeated reflective discovery, but the execution order remains FIFO for submitted events.
 * When no listeners are registered for a given method name and source, the event is silently
 * skipped.
 *
 * <p>Use this class when you need a lightweight, per-source event bus without committing to a
 * broader framework. Typical usage registers listeners tied to a particular publisher object and
 * calls {@link #fire(EventObject, String)} whenever a state change occurs. The dispatcher remains
 * mutable throughout its lifetime: you may add or remove listeners at any time, adjust the thread
 * priority, or install a custom {@link ExceptionHandler} to capture reflective failures. The class
 * is not intended for high-throughput scenarios; the single-threaded consumer ensures predictable
 * ordering but limits parallel delivery.
 *
 * <ul>
 *   <li>Queues events for asynchronous delivery on a dedicated daemon thread.
 *   <li>Matches listeners by exact event source instance and method name.
 *   <li>Caches reflective lookups to minimize per-event overhead.
 *   <li>Falls back to logging when no {@link ExceptionHandler} is configured.
 * </ul>
 *
 * @see ExceptionHandler
 * @author Justin Chapweske
 */
public class ReflectiveEventDispatch implements Runnable {

  private static final Logger LOGGER = Logger.getLogger(ReflectiveEventDispatch.class.getName());

  private final Map<Tuple, Method> methodCache = new HashMap<>();
  private final Map<Object, Map<String, Set<EventListener>>> listeners = new HashMap<>();
  // Holds either Tuple(event, methodName) or a sentinel (this) to signal shutdown
  private final ArrayDeque<Object> eventQueue = new ArrayDeque<>();
  private final Thread thread;
  private boolean dispatchThreadStarted;
  private ExceptionHandler handler;

  /**
   * Creates a new dispatcher instance with a dedicated daemon thread.
   *
   * <p>The constructor initializes internal state and prepares the dispatch thread. The thread
   * starts lazily when the first event is queued. Callers can register listeners and install an
   * {@link ExceptionHandler} before any asynchronous work begins.
   */
  public ReflectiveEventDispatch() {
    this.thread = new Thread(this, "Reflective Dispatch#" + hashCode());
    this.thread.setDaemon(true);
  }

  /**
   * Registers an exception handler that receives failures raised during listener invocation.
   *
   * <p>When set, the handler is invoked with an {@link ExceptionEvent} every time reflective
   * invocation of a listener method throws an exception. Passing {@code null} restores the default
   * behavior, which logs the exception at {@link Level#SEVERE}. The handler runs on the dispatch
   * thread, so heavy processing may delay further event delivery.
   *
   * @param h handler invoked for dispatch-time exceptions; may be {@code null} to disable custom
   *     handling.
   */
  public void setExceptionHandler(ExceptionHandler h) {
    handler = h;
  }

  /**
   * Adds a listener for a single method name for events originating from the provided source.
   *
   * <p>This overload is a convenience wrapper around {@link #addListener(Object, EventListener,
   * String[])}, registering the listener for exactly one method name. The registration is tied to
   * the specific source instance; events fired from other sources are not delivered to this
   * listener. Duplicate registrations for the same source and method name are idempotent because
   * listeners are stored in a {@link Set}.
   *
   * @param source event source instance that must equal {@link EventObject#getSource()} for the
   *     listener to be notified; must not be {@code null}.
   * @param el listener object that exposes a public method named {@code methodName} accepting the
   *     event type; must not be {@code null}.
   * @param methodName name of the listener method to invoke; compared literally and case-sensitive.
   */
  public synchronized void addListener(Object source, EventListener el, String methodName) {
    this.addListener(source, el, new String[] {methodName});
  }

  /**
   * Adds a listener for multiple method names for events originating from the provided source.
   *
   * <p>Each supplied method name is recorded against the given source instance. When {@link
   * #fire(EventObject, String)} is later called with a matching source and method name, the
   * corresponding method on the listener is invoked reflectively. Listener lookups are synchronized
   * and thread-safe; registrations may occur while the dispatcher is actively delivering other
   * events. Method names are kept as-is and must match the actual public listener method signature.
   *
   * <pre>{@code
   * dispatcher.addListener(source, listener, new String[] {"onSave", "onClose"});
   * dispatcher.fire(new EventObject(source), "onSave");
   * }</pre>
   *
   * @param source event source instance that must match {@link EventObject#getSource()} during
   *     dispatch for delivery to occur.
   * @param el listener instance exposing public methods named in {@code methodNames} that accept a
   *     single {@link EventObject} subtype argument.
   * @param methodNames array of method names to register; entries must be non-null and
   *     case-sensitive.
   */
  public synchronized void addListener(Object source, EventListener el, String[] methodNames) {
    Map<String, Set<EventListener>> hm = listeners.computeIfAbsent(source, _ -> new HashMap<>());

    for (String methodName : methodNames) {
      hm.computeIfAbsent(methodName, _ -> new HashSet<>()).add(el);
    }
  }

  /**
   * Removes a single listener registration for the provided source and method name.
   *
   * <p>This convenience overload delegates to {@link #removeListener(Object, EventListener,
   * String[])}. Removal is synchronized with dispatch activity, ensuring that no additional events
   * for the specified method and source are delivered to the listener once the call completes.
   *
   * @param source event source used during registration; must not be {@code null}.
   * @param el listener instance to deregister for the specified method name.
   * @param methodName method name previously registered for {@code el}; must have been added or an
   *     exception is thrown.
   * @throws IllegalArgumentException if the listener was not registered for the method name and
   *     source.
   */
  public synchronized void removeListener(Object source, EventListener el, String methodName) {
    this.removeListener(source, el, new String[] {methodName});
  }

  /**
   * Removes a listener registration for multiple method names tied to the specified source.
   *
   * <p>Each provided method name is removed independently. If the source or listener were not
   * previously registered for any of the names, this method throws {@link IllegalArgumentException}
   * to indicate a programming error. Removal is synchronized with dispatching to ensure no new
   * deliveries occur for removed mappings after this call returns.
   *
   * @param source event source whose registrations should be removed; must be the exact object used
   *     during {@link #addListener(Object, EventListener, String[])}.
   * @param el listener instance previously registered for the given method names and source.
   * @param methodNames method names to deregister for {@code el}; names must have been registered
   *     or an exception is thrown.
   * @throws IllegalArgumentException if the source or listener was not registered for any provided
   *     method name.
   */
  public synchronized void removeListener(Object source, EventListener el, String[] methodNames) {
    Map<String, Set<EventListener>> hm = listeners.get(source);
    if (hm == null) {
      throw new IllegalArgumentException("Listener not registered.");
    }
    for (String methodName : methodNames) {
      Set<EventListener> set = hm.get(methodName);
      if (set == null || !set.contains(el)) {
        throw new IllegalArgumentException("Listener not registered.");
      }

      set.remove(el);
    }
  }

  /**
   * Queues an event for asynchronous dispatch to listeners of the given method.
   *
   * <p>The event is appended to the tail of the queue and delivered in FIFO order by the dispatcher
   * thread. Delivery occurs only when the event's source equals the {@code source} used during
   * listener registration and when the {@code methodName} matches one of the listener's registered
   * method names. This method returns immediately; it does not wait for completion or surface
   * listener exceptions.
   *
   * @param ev event instance to deliver; its {@link EventObject#getSource()} must match a
   *     registered source for delivery to occur.
   * @param methodName name of the listener method to target; compared literally and case-sensitive
   *     against registered names.
   */
  public synchronized void fire(EventObject ev, String methodName) {
    startDispatchThreadIfNeeded();
    eventQueue.add(new Tuple(ev, methodName));
    this.notifyAll();
  }

  /**
   * Signals the dispatch thread to stop after processing queued events.
   *
   * <p>A sentinel object is placed on the queue; once encountered, the dispatch loop exits after
   * completing any prior work. Events enqueued after this call may or may not be processed
   * depending on timing, so callers should stop submitting new events before invoking this method.
   * The method is idempotent but does not interrupt a listener currently executing.
   */
  public synchronized void close() {
    // Place this in the queue to signify that we are done.
    eventQueue.add(this);
    this.notifyAll();
  }

  private void startDispatchThreadIfNeeded() {
    if (!dispatchThreadStarted) {
      thread.start();
      dispatchThreadStarted = true;
    }
  }

  /**
   * Main dispatch loop executed by the internal daemon thread.
   *
   * <p>The loop waits for queued events, exits when {@link #close()} enqueues the sentinel marker,
   * and otherwise delegates each unit of work to {@link #dispatch(DispatchWork)}. It preserves the
   * order in which events were queued and performs listener invocation on the same dedicated thread
   * to simplify synchronization concerns for clients. Applications typically never call this method
   * directly because it is invoked automatically after the first event is submitted.
   */
  @Override
  public void run() {
    while (true) {
      DispatchWork work;
      try {
        work = takeNextWork();
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        return;
      }
      if (work == null) {
        return;
      }
      dispatch(work);
    }
  }

  private DispatchWork takeNextWork() throws InterruptedException {
    synchronized (this) {
      while (true) {
        while (eventQueue.isEmpty()) {
          this.wait();
        }
        Object obj = eventQueue.removeFirst();
        if (obj == this) {
          return null;
        }
        Tuple tuple = (Tuple) obj;
        EventObject event = (EventObject) tuple.getLeft();
        String methodName = (String) tuple.getRight();
        Map<String, Set<EventListener>> hm = listeners.get(event.getSource());
        Set<EventListener> set = hm == null ? null : hm.get(methodName);
        if (set == null || set.isEmpty()) {
          continue;
        }
        return new DispatchWork(event, methodName, new HashSet<>(set));
      }
    }
  }

  private void dispatch(DispatchWork work) {
    for (EventListener el : work.listeners()) {
      try {
        Class<? extends EventListener> listenerClass = el.getClass();
        Class<? extends EventObject> eventClass = work.event().getClass();

        Tuple cacheKey = new Tuple(listenerClass, new Tuple(work.methodName(), eventClass));
        Method method = methodCache.get(cacheKey);
        if (method == null) {
          Class<?>[] parameterTypes = new Class<?>[] {eventClass};
          method = Util.getPublicMethod(listenerClass, work.methodName(), parameterTypes);
          methodCache.put(cacheKey, method);
        }
        Object[] args = new Object[] {work.event()};
        method.invoke(el, args);
      } catch (Exception e) {
        handleDispatchException(e);
      }
    }
  }

  private void handleDispatchException(Exception exception) {
    if (handler != null) {
      handler.handleException(new ExceptionEvent(this, exception));
    } else {
      LOGGER.log(Level.SEVERE, "Exception while dispatching event", exception);
    }
  }

  private record DispatchWork(EventObject event, String methodName, Set<EventListener> listeners) {}
}
