package network.crypta.node;

/**
 * Callback interface notified when a client request completes.
 *
 * <p>The node invokes this listener once a request reaches a terminal state (success or failure).
 * It is conceptually similar to a request-sender listener, but with two guarantees that are
 * important for client code:
 *
 * <ol>
 *   <li>Any internal request lock is released before a callback method is invoked. This prevents
 *       listener implementations from deadlocking if they call back into the node.
 *   <li>Failures are surfaced as a low-level exception that captures the underlying cause for the
 *       specific request type.
 * </ol>
 *
 * <p>Implementations must be fast and should avoid blocking operations. Callbacks may be invoked on
 * a node-internal thread. Each request results in one success or one failure callback.
 */
public interface RequestCompletionListener {

  /**
   * Invoked when the request completes successfully.
   *
   * <p>Any associated key or completion signal is handled by the node prior to invoking this
   * method. Implementations can assume the request is no longer held by internal locks when this
   * callback runs.
   */
  void onSucceeded();

  /**
   * Invoked when the request cannot be completed.
   *
   * @param e non-null low-level failure describing the cause (e.g., timeout, not found, routing
   *     error). The exact subtype encodes details relevant to the request.
   */
  void onFailed(LowLevelGetException e);
}
