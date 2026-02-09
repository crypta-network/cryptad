package com.onionnetworks.util;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.util.EventListener;
import java.util.EventObject;
import java.util.Objects;

/**
 * Dispatches {@link Runnable} instances through {@link ReflectiveEventDispatch} while providing
 * synchronous and asynchronous invocation helpers.
 *
 * <p>This dispatcher registers itself as a listener for an internal {@link InvokeEvent} and routes
 * events to the {@link #invoke(InvokeEvent)} handler. Clients submit work with {@link
 * #invokeLater(Runnable)} to enqueue execution without blocking, or with {@link
 * #invokeAndWait(Runnable)} when they must wait for completion. Each submitted task is wrapped in
 * an event carrying a per-invocation monitor so the caller can block without interfering with other
 * requests.
 *
 * <p>The class is thread-safe for concurrent submissions: every {@link InvokeEvent} owns its own
 * lock and completion flag, and the dispatch logic synchronizes on that lock only for the lifetime
 * of the event. Execution order follows the underlying {@link ReflectiveEventDispatch} mechanics,
 * so long-running tasks may delay later ones; callers should choose between the async and sync
 * entry points accordingly. Typical usage is to share a single {@code InvokingDispatch} instance
 * across components that need to schedule work onto a dedicated dispatch thread.
 *
 * <ul>
 *   <li>Asynchronous: {@link #invokeLater(Runnable)} enqueues and returns immediately.
 *   <li>Synchronous: {@link #invokeAndWait(Runnable)} blocks until the runnable completes or the
 *       thread is interrupted.
 *   <li>Handler: {@link #invoke(InvokeEvent)} performs execution and signals completion.
 * </ul>
 *
 * @see ReflectiveEventDispatch
 */
public class InvokingDispatch extends ReflectiveEventDispatch implements EventListener {

  /** Event name used to identify invoke requests within the reflective dispatch machinery. */
  public static final String INVOKE_EVENT_NAME = "invoke";

  /**
   * Creates a new dispatcher and registers it to listen for its own invoking events, enabling later
   * calls to {@link #invokeLater(Runnable)} and {@link #invokeAndWait(Runnable)}.
   */
  public InvokingDispatch() {
    super();
    addListener(this, this, INVOKE_EVENT_NAME);
  }

  // can't be inner class unless we create a public interface for invoke()
  /**
   * Handles an {@link InvokeEvent} by running the enclosed task and waking any waiting threads.
   *
   * <p>Execution occurs on the dispatch thread managed by {@link ReflectiveEventDispatch}. The
   * method marks the event as completed and notifies all waiters on the event's lock so callers of
   * {@link #invokeAndWait(Runnable)} can resume. The runnable is executed exactly once per event.
   *
   * @param ev event carrying the runnable and completion monitor; must not be {@code null}.
   */
  public void invoke(InvokeEvent ev) {
    ev.getRunnable().run();
    synchronized (ev.getLock()) {
      ev.markCompleted();
      ev.getLock().notifyAll();
    }
  }

  /**
   * Enqueues a runnable for execution on the dispatch thread without blocking the caller.
   *
   * <p>The runnable is wrapped in an {@link InvokeEvent} and fired through the reflective dispatch.
   * Callers should prefer this method for fire-and-forget tasks or when they do not need to observe
   * completion.
   *
   * @param r runnable to execute; must be non-null and ready for a single invocation.
   */
  public void invokeLater(Runnable r) {
    fire(new InvokeEvent(this, r), INVOKE_EVENT_NAME);
  }

  /**
   * Submits a runnable to the dispatch thread and blocks until it completes or the thread is
   * interrupted.
   *
   * <p>The caller waits on a per-event lock, so different submissions do not interfere with one
   * another. If the current thread is interrupted while waiting, the method throws {@link
   * InterruptedException} and leaves the interrupt status cleared. The runnable still executes
   * unless dispatching is interrupted upstream.
   *
   * <pre>{@code
   * InvokingDispatch dispatch = new InvokingDispatch();
   * dispatch.invokeAndWait(() -> performWork());
   * }</pre>
   *
   * @param r runnable to execute; must be non-null and safe to run exactly once.
   * @throws InterruptedException if the calling thread is interrupted while waiting for completion.
   */
  public void invokeAndWait(Runnable r) throws InterruptedException {
    InvokeEvent ev = new InvokeEvent(this, r);
    Object lock = ev.getLock();
    synchronized (lock) {
      fire(ev, INVOKE_EVENT_NAME);
      while (!ev.isCompleted()) {
        lock.wait();
      }
    }
  }

  /**
   * Event envelope that transports a {@link Runnable} and carries completion state for synchronous
   * callers.
   *
   * <p>Each instance owns a dedicated lock object used by {@link InvokingDispatch} to coordinate
   * wait/notify interactions. The completion flag advances from {@code false} to {@code true} when
   * {@link #markCompleted()} is called by the dispatcher after the runnable finishes. Instances are
   * single-use and not thread-safe beyond the guarded access provided by {@link
   * InvokingDispatch#invokeAndWait(Runnable)}.
   */
  public static class InvokeEvent extends EventObject {
    @Serial private static final long serialVersionUID = 1L;

    /** Task to run on the dispatch thread; supplied by the creator and never mutated. */
    private final transient Runnable runnable;

    /** Per-event monitor used to coordinate waiting callers and completion notification. */
    private transient Object lock = new Object();

    /** Tracks whether the runnable has finished executing; guarded by {@link #lock}. */
    private boolean completed;

    /**
     * Creates a new invoking event carrying the specified runnable and source reference.
     *
     * @param source originator of the event, passed to {@link EventObject}; must be non-null.
     * @param r runnable to execute when dispatched; must be non-null.
     */
    public InvokeEvent(Object source, Runnable r) {
      super(source);
      this.runnable = Objects.requireNonNull(r);
    }

    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
      in.defaultReadObject();
      this.lock = new Object();
    }

    /**
     * Returns the runnable associated with this event.
     *
     * @return runnable to be executed; never {@code null} and intended for a single run.
     */
    public Runnable getRunnable() {
      return runnable;
    }

    /**
     * Returns the lock object used for coordinating wait/notify between dispatcher and callers.
     *
     * @return dedicated monitor for this event; callers should synchronize before waiting.
     */
    public Object getLock() {
      return lock;
    }

    /**
     * Indicates whether the runnable has completed execution.
     *
     * @return {@code true} after {@link #markCompleted()} is called; {@code false} otherwise.
     */
    public boolean isCompleted() {
      return completed;
    }

    /**
     * Marks this event as completed after the runnable finishes. Callers should synchronize on
     * {@link #getLock()} when invoking this method to ensure the completion flag is visible to
     * waiting threads.
     */
    public void markCompleted() {
      this.completed = true;
    }
  }
}
