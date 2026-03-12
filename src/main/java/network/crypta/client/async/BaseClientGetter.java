package network.crypta.client.async;

import java.io.Serial;
import java.io.Serializable;
import network.crypta.node.RequestClient;

/**
 * Base type for asynchronous, client-initiated GET-style requests.
 *
 * <p>This abstract class provides a minimal foundation for request implementations that retrieve
 * data on behalf of a client and signal completion via {@link GetCompletionCallback}. It builds on
 * {@link ClientRequester} for scheduling and lifecycle integration with the node, while keeping the
 * concrete retrieval logic in subclasses. Typical usage is to subclass this type, pass a priority
 * and {@link RequestClient} to the constructor, and then rely on the request framework to execute
 * and invoke completion callbacks.
 *
 * <p>Lifecycle overview: an instance is constructed, registered with the scheduler (via the parent
 * {@code ClientRequester}), executed by worker threads, and finally reports success or failure
 * through the callback interface. Instances are generally not thread-safe for external mutation;
 * treat them as owned by the request framework once scheduled. Subclasses may hold additional
 * state, but should avoid exposing mutable state to callers during execution. Priority classes and
 * exact queueing semantics are determined by the scheduler and may influence fairness, latency, and
 * throughput trade-offs.
 *
 * <ul>
 *   <li>Responsibility: represent a client-initiated "getter" request.
 *   <li>Integration: delegates scheduling and accounting to {@link ClientRequester}.
 *   <li>Completion: reports outcomes via {@link GetCompletionCallback}.
 * </ul>
 *
 * @see ClientRequester
 * @see GetCompletionCallback
 * @see RequestClient
 */
public abstract class BaseClientGetter extends ClientRequester
    implements GetCompletionCallback, Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Create a new getter associated with a client and a scheduler priority.
   *
   * <p>The provided {@code priorityClass} is forwarded to the request framework and may influence
   * ordering and fairness relative to other requests. The {@code requestClient} identifies the
   * initiating client, supplies context, and receives accounting/feedback as the request proceeds.
   * After construction, the instance is ready to be scheduled by the surrounding infrastructure.
   * This constructor performs no I/O.
   *
   * @param priorityClass scheduler priority band to apply to this request; must be a value
   *     recognized by the request framework; callers should use constants provided by the system or
   *     application configuration; negative or unsupported values are not recommended.
   * @param requestClient non-null client context used for ownership, attribution, and callbacks;
   *     the same instance should remain valid for the lifetime of the request.
   */
  protected BaseClientGetter(short priorityClass, RequestClient requestClient) {
    super(priorityClass, requestClient);
  }

  /**
   * No-arg constructor to support serialization frameworks and subclass initialization.
   *
   * <p>Some serialization/deserialization mechanisms and reflective instantiation paths require a
   * zero-argument constructor. Subclasses may also use this for deferred dependency injection in
   * their initialization blocks. Instances created with this constructor are not fully initialized
   * until the owning framework or subclass sets the required fields; callers should not schedule or
   * execute requests created this way until initialization is complete.
   */
  protected BaseClientGetter() {}
}
