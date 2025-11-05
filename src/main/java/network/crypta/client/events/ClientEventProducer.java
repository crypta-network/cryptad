package network.crypta.client.events;

import network.crypta.client.async.ClientContext;

/**
 * Produces and dispatches client-layer events to registered listeners.
 *
 * <p>Implementations of this interface act as the source of truth for events that describe progress
 * and notable occurrences during client operations. A producer maintains a set of {@code
 * ClientEventListener} instances and, when appropriate, delivers {@code ClientEvent} instances to
 * each listener. Typical use is within request pipelines, where producers surface human-readable
 * updates (e.g., expected sizes, MIME types, or compression status) and allow external components
 * to observe behavior without coupling to internal control flow.
 *
 * <p>Dispatch strategy (synchronous vs. asynchronous) is implementation-dependent; callers must not
 * assume a particular threading model. To avoid re-entrancy surprises and UI stalls, producers
 * should strive to dispatch quickly, and listeners should avoid blocking. A common pattern is to
 * pass a {@code ClientContext} alongside each event so listeners can schedule heavier work on
 * background executors rather than executing it inline.
 *
 * <ul>
 *   <li>Responsibilities: track listeners, emit events reliably, document ordering guarantees.
 *   <li>Threading: may call listeners from worker or IO threads; keep handlers fast.
 *   <li>Failure: producers should isolate listener failures to prevent cascading errors.
 * </ul>
 *
 * @see ClientEvent
 * @see ClientEventListener
 * @author oskar
 */
public interface ClientEventProducer {

  /**
   * Sends the event to all currently registered listeners with contextual services.
   *
   * <p>Each registered listener is invoked once for the given event. Implementations may choose to
   * deliver callbacks synchronously on the caller's thread or asynchronously on internal executors.
   * Listeners should treat the delivered event as immutable and must avoid long blocking work in
   * the callback. When persistence or I/O is necessary, prefer using the provided {@code
   * ClientContext} to enqueue the work rather than performing it inline.
   *
   * <pre>{@code
   * // Example: producer dispatch
   * producer.produceEvent(new StartedCompressionEvent(), context);
   * }</pre>
   *
   * @param ce the event instance to raise; non-null; conveys a human-friendly description and a
   *     stable event code suitable for filtering or correlation.
   * @param context execution and persistence context associated with the event; non-null; use it to
   *     schedule follow-up work and avoid blocking inside listener callbacks.
   */
  void produceEvent(ClientEvent ce, ClientContext context);

  /**
   * Adds a listener that will receive all subsequent events produced by this instance.
   *
   * <p>Implementations may disallow duplicate registrations or coalesce them; callers should not
   * rely on a listener being invoked more than once per event. Registration and removal need to be
   * thread-safe if performed concurrently with event dispatch.
   *
   * @param cel the listener to register; non-null; should return quickly and avoid blocking the
   *     dispatch thread; may be called from arbitrary worker threads.
   */
  void addEventListener(ClientEventListener cel);

  /**
   * Removes a listener so it no longer receives events from this instance.
   *
   * <p>After successful removal, the listener will not be invoked for any future events. If the
   * listener was not previously registered, the method has no effect. Implementations should ensure
   * removal is safe to call concurrently with dispatch and does not invalidate internal iteration.
   *
   * @param cel the listener to remove; non-null; the exact matching semantics are implementation
   *     dependent (reference equality is common).
   * @return {@code true} if a previously registered listener was removed; {@code false} when no
   *     matching listener was found or removal did not change the registration set.
   */
  boolean removeEventListener(ClientEventListener cel);
}
