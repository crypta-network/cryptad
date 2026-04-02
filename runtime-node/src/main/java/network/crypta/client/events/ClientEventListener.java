package network.crypta.client.events;

import network.crypta.client.async.ClientContext;

/**
 * Receives and acts upon client-layer events emitted by producers.
 *
 * <p>Implementations of this interface subscribe to events created by components such as request
 * starters, schedulers, and storage pipelines. A listener typically logs, aggregates, forwards, or
 * renders event information to users without altering the underlying control flow. The contract is
 * intentionally lightweight: a listener is invoked for each event and may perform side effects
 * appropriate to its role (e.g., append to a log, update a progress bar, or enqueue follow-up
 * work).
 *
 * <p>Invocation can be synchronous or asynchronous depending on the producer. Implementations must
 * return promptly and avoid long blocking operations in the callback. When database access or other
 * persistence-affecting work is required, schedule it through the provided {@code ClientContext}
 * rather than performing it inline. Treat event objects as immutable and thread-safe; listeners
 * should not retain references for mutation or cross-thread modification.
 *
 * <ul>
 *   <li>Responsibilities: observe events, perform minimal processing, delegate heavier work.
 *   <li>Concurrency: may be called from internal worker threads; keep handlers fast.
 *   <li>Failure model: listeners should be defensive and avoid throwing unchecked exceptions.
 * </ul>
 *
 * @author oskar
 * @see ClientEvent
 * @see ClientEventProducer
 */
public interface ClientEventListener {

  /**
   * Receives a single event raised by a producer, with contextual services for follow-up work.
   *
   * <p>Producers call this method zero or more times during a request or background operation.
   * Implementations should keep processing quick and non-blocking; if additional I/O or persistence
   * is required, use the {@code ClientContext} to offload the work to the appropriate executors or
   * job runners. The event object is intended for read-only inspection. Implementations may choose
   * to ignore specific event kinds or to coalesce repeated signals.
   *
   * <pre>{@code
   * // Example: log significant events and schedule DB work when needed
   * public void receive(ClientEvent e, ClientContext ctx) {
   *   LOG.info("{}", e.getDescription());
   *   // Use ctx to enqueue persistence tasks instead of blocking here.
   * }
   * }</pre>
   *
   * @param ce the event instance being delivered; non-null; consumers must not modify or retain it
   *     for mutation and should treat it as immutable data.
   * @param context execution and persistence context associated with the event; may not carry an
   *     active database transaction; use it to schedule database work instead of performing it
   *     inline in the callback.
   */
  void receive(ClientEvent ce, ClientContext context);
}
