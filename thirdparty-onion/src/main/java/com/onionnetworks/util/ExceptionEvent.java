package com.onionnetworks.util;

import java.util.EventObject;

/**
 * Carries a {@link Throwable} captured by a component together with the source object that raised
 * it so that listeners can react uniformly through an {@code ExceptionHandler} pipeline.
 *
 * <p>This event is created as soon as an exception needs to be propagated outside the immediate
 * call site, keeping both the originating object (the {@code source}) and the original throwable
 * instance intact. Consumers typically enqueue or broadcast the event rather than throwing it
 * directly, allowing logging, user notification, or recovery workflows to be centralized. The class
 * is deliberately lightweight: it stores only the given source and exception reference and performs
 * no copying or wrapping, which means the lifecycle of the contained exception is managed entirely
 * by the caller. Instances are immutable after construction and are safe to share across threads
 * provided the referenced throwable itself is treated as immutable.
 *
 * <ul>
 *   <li>Encapsulates exception details without altering stack traces or causes.
 *   <li>Maintains the original event source to aid routing and diagnostics.
 *   <li>Designed for asynchronous dispatch or observer-style handlers.
 * </ul>
 *
 * @author Justin Chapweske
 */
public class ExceptionEvent extends EventObject {

  /**
   * The original throwable instance associated with this event; stored exactly as supplied so
   * handlers can inspect or rethrow it without losing stack trace or suppressed exception details.
   */
  Throwable t;

  /**
   * Creates a new event that binds the given source object to the supplied throwable for later
   * dispatch to exception listeners.
   *
   * <p>The constructor performs no validation or wrapping; callers are expected to pass a source
   * that meaningfully identifies the context where the failure originated. This makes it possible
   * for downstream handlers to group, filter, or route events by subsystem while still having
   * access to the complete throwable for logging or rethrowing. The same throwable reference is
   * retained, so any additional suppression or detail messages added later will be visible to
   * handlers that consume the event.
   *
   * <pre>{@code
   * try {
   *   service.execute();
   * } catch (Throwable ex) {
   *   dispatcher.fire(new ExceptionEvent(this, ex));
   * }
   * }</pre>
   *
   * @param source the object that observed or caught the exception; never {@code null} when used
   *     with {@link EventObject} listeners.
   * @param t the throwable being propagated; may be any checked or unchecked failure instance
   *     produced by the source.
   */
  public ExceptionEvent(Object source, Throwable t) {
    super(source);
    this.t = t;
  }

  /**
   * Returns the throwable instance that this event carries for downstream handling.
   *
   * <p>The returned reference is the exact object supplied at construction time, allowing callers
   * to inspect stack traces, causes, or custom fields without serialization or copying overhead.
   * Callers should avoid mutating the throwable in ways that would confuse other listeners unless
   * coordinated externally; otherwise this method is safe to call repeatedly and does not alter the
   * stored state.
   *
   * @return the original throwable associated with this event; may be {@code null} if the creator
   *     intentionally forwarded an absent failure.
   */
  public Throwable getException() {
    return t;
  }
}
