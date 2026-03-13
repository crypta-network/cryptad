package com.onionnetworks.util;

import java.io.Serial;
import java.util.EventObject;

/**
 * Event wrapper that carries a {@link Runnable} callback to be executed by the listener handling
 * the event. The class extends {@link EventObject} so it retains the original event source while
 * providing a lightweight container for deferred or thread-hopping execution strategies common in
 * Swing, executor-based utilities, and other dispatcher loops.
 *
 * <p>Typical usage is to construct an instance with the originating component as the source and a
 * callback that performs the actual work. Listeners or dispatch queues can then pull the runnable
 * from {@link #getRunnable()} and execute it in the appropriate thread or scheduling context. The
 * {@code Runnable} reference is marked {@code transient} so that accidental serialization of event
 * queues does not attempt to persist arbitrary executable state; only the event source survives
 * serialization. Instances are immutable after construction, making them safe to share across
 * threads provided the referenced runnable is itself thread-safe or confined to the execution
 * context that eventually runs it.
 *
 * <ul>
 *   <li>Retains the event source for diagnostics and routing.
 *   <li>Allows listeners to defer execution until a chosen thread is available.
 *   <li>Uses immutability to simplify sharing between producer and consumer.
 * </ul>
 *
 * @see Runnable
 * @see EventObject
 */
public class InvokeEvent extends EventObject {
  @Serial private static final long serialVersionUID = 234594476951043607L;

  private final transient Runnable r;

  /**
   * Creates a new invoking event that associates the given source object with a runnable callback
   * the listener may execute. The constructor does not validate the runnable; callers decide
   * whether a {@code null} runnable is meaningful in their dispatch model. The source parameter
   * must not be {@code null} because {@link EventObject} enforces that requirement and will throw
   * {@link NullPointerException} if violated. Once created, the event captures the provided values
   * and exposes them immutably to downstream handlers.
   *
   * @param source non-null origin of the event, typically the publisher or owning component
   * @param r runnable callback to execute when handling the event; may be {@code null} if handled
   *     defensively
   */
  public InvokeEvent(Object source, Runnable r) {
    super(source);
    this.r = r;
  }

  /**
   * Returns the runnable callback associated with this event. The method does not execute the
   * runnable; it merely exposes the reference so the caller can decide how and where to run it,
   * whether immediately, on an event-dispatch thread, or after additional filtering. When the
   * runnable is {@code null}, listeners should treat the event as a marker or provide a safe
   * fallback. The returned reference is the same instance supplied to the constructor and is not
   * copied or synchronized, so callers must ensure any execution respects the runnable's own
   * thread-safety requirements.
   *
   * @return runnable supplied at construction time; may be {@code null} and is returned as-is
   */
  public Runnable getRunnable() {
    return r;
  }
}
