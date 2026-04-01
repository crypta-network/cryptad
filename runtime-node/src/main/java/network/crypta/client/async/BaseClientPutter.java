package network.crypta.client.async;

import java.io.Serial;
import java.io.Serializable;
import network.crypta.node.RequestClient;

/**
 * Base class for client-side put operations, including site inserts, implemented at the {@link
 * ClientRequester} layer.
 *
 * <p>This type coordinates the high-level life cycle of a client put request while delegating
 * algorithmic and storage details to concrete subclasses. Typical usage is to instantiate a
 * subclass with an application-specific {@code priorityClass} and {@link RequestClient} and let the
 * scheduler drive state transitions. Subclasses receive transition callbacks via {@link
 * #onTransition(ClientPutState, ClientPutState, ClientContext)} and can persist or report progress
 * as appropriate for the client API.
 *
 * <p>The instance represents a single logical put operation and is not thread-safe unless the
 * subclass states otherwise. Implementations should assume that transition callbacks may occur on
 * internal scheduler threads and should avoid blocking them for extended periods. State changes are
 * monotonic toward completion or failure according to the concrete strategy.
 *
 * <ul>
 *   <li>Defines the minimal success threshold via {@link #getMinSuccessFetchBlocks()}.
 *   <li>Exposes a hook for state changes through {@link #onTransition(ClientPutState,
 *       ClientPutState, ClientContext)}.
 *   <li>Provides a no-op {@link #dump()} method that subclasses may override for diagnostics.
 * </ul>
 *
 * <p><strong>Warning:</strong> Changing non-transient fields of {@code Serializable} classes can
 * alter serialization compatibility, potentially restarting downloads or losing uploads when
 * restoring persisted state.
 *
 * @see ClientRequester
 * @see ClientPutState
 * @see ClientContext
 * @see RequestClient
 */
public abstract class BaseClientPutter extends ClientRequester {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Constructs a new instance for deserialization and subclass use.
   *
   * <p>This protected no‑arg constructor exists because {@link Serializable} is implemented by the
   * parent class. Subclasses may rely on it when frameworks or persistence layers instantiate the
   * object reflectively. No fields are initialized beyond those performed by the supertype.
   */
  protected BaseClientPutter() {}

  /**
   * Constructs a putter with the given priority and client association.
   *
   * <p>The priority class influences scheduling relative to other client requests. The associated
   * {@link RequestClient} identifies the logical owner of this operation for accounting and
   * callbacks. Implementations do not validate the priority range; callers should provide values
   * consistent with the surrounding scheduler configuration.
   *
   * @param priorityClass application-defined priority classification used by internal schedulers;
   *     provide values consistent with configured ranges; negative values are typically avoided.
   * @param requestClient client identity used for attribution, callbacks, and quota enforcement;
   *     must not be {@code null} when scheduling the request lifecycle.
   */
  protected BaseClientPutter(short priorityClass, RequestClient requestClient) {
    super(priorityClass, requestClient);
  }

  /**
   * Emits internal state useful for diagnostics; default implementation does nothing.
   *
   * <p>Subclasses may override this method to print or log concise information that helps
   * troubleshoot a stalled or failing request. Implementations should avoid heavy I/O and must not
   * change observable state. This method is intended to be safe to call at any time during the
   * request lifecycle.
   */
  public void dump() {
    // Do nothing
  }

  /**
   * Notifies the instance that its state has transitioned within the put lifecycle.
   *
   * <p>Implementations may update progress indicators, persist checkpoints, or trigger downstream
   * actions in response to the transition. Callers guarantee that {@code from} and {@code to}
   * correspond to successive states for the same request. Implementations should be idempotent
   * where feasible and avoid long blocking operations; the callback may run on internal scheduler
   * threads.
   *
   * @param from previous state of the put operation; may be {@code null} at initialization when no
   *     prior state exists.
   * @param to next state entered by the operation; represents the current authoritative status and
   *     should be treated as immutable by the callee.
   * @param context execution context carrying services and configuration relevant to the
   *     transition; never {@code null} during normal operation.
   */
  public abstract void onTransition(ClientPutState from, ClientPutState to, ClientContext context);

  /**
   * Returns the minimal number of successful fetch blocks required by this strategy.
   *
   * <p>The value is used by scheduling and progress reporting to decide whether the put operation
   * has achieved a sufficient success threshold to be considered viable. Subclasses define the
   * exact semantics, which typically reflect coding/redundancy parameters or verification needs.
   *
   * @return a non-negative integer indicating the threshold of successful fetch blocks that signals
   *     sufficient progress for this operation; callers treat the value as read-only.
   */
  public abstract int getMinSuccessFetchBlocks();
}
