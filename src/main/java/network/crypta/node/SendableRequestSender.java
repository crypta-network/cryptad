package network.crypta.node;

import network.crypta.client.async.ChosenBlock;
import network.crypta.client.async.ClientContext;

/**
 * Sends a single, non-persistent client request selected by the scheduler.
 *
 * <p>Implementations start network I/O for a chosen request and must report completion or failure
 * via the callbacks exposed by {@link ChosenBlock}. State is intentionally not persisted across
 * process restarts; callers treat this as a best-effort, in-memory dispatch layer.
 *
 * <p>Threading: callers may invoke methods on this interface from scheduler or worker threads.
 * Implementations should avoid long blocking operations unless {@link #sendIsBlocking()} returns
 * {@code true}, and should be safe to call for different requests concurrently.
 *
 * <p>Side effects: may enqueue packets, update in-memory accounting, and invoke callbacks on the
 * provided {@link ChosenBlock}. Implementations must not log or expose confidential material such
 * as keys or credentials.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public interface SendableRequestSender {

  /**
   * Starts the actual network operation for a chosen request.
   *
   * <p>This is called only by {@code RequestStarter}. The implementation should initiate the send
   * using the provided {@code node} and the key information contained in {@code request}. It must
   * signal completion (success or failure) using the callbacks on {@link ChosenBlock}; those
   * callbacks also perform any required local bookkeeping (for example, removing the key from a
   * local "fetching" set when appropriate).
   *
   * <p>Preconditions: {@code request} contains a selected key and a {@code SendableRequestItem}.
   * Implementations should treat inputs as non-null.
   *
   * <p>Postconditions: when this method returns {@code true}, the send has been initiated and the
   * result will be reported asynchronously (unless {@link #sendIsBlocking()} returns {@code true}).
   * When this method returns {@code false}, no send occurred; the caller may remove the request if
   * it has not already been removed by a callback.
   *
   * <p>Side effects: may schedule asynchronous work and invoke callbacks on {@code request}. The
   * method may block depending on {@link #sendIsBlocking()}.
   *
   * @param node the node client core used to perform the send
   * @param sched the scheduler from which the request was dispatched
   * @param context shared client context/state for the operation
   * @param request the chosen block containing the key, request item, and callbacks
   * @return {@code true} if a send was initiated; {@code false} otherwise
   */
  boolean send(
      NodeClientCore node, RequestScheduler sched, ClientContext context, ChosenBlock request);

  /**
   * Indicates whether {@link #send(NodeClientCore, RequestScheduler, ClientContext, ChosenBlock)}
   * performs a blocking operation.
   *
   * <p>When this returns {@code true}, callers should assume {@code send(...)} may block the
   * calling thread for a noticeable duration (e.g., until a synchronous attempt completes). When it
   * returns {@code false}, callers may assume the implementation schedules the work and returns
   * promptly, reporting the outcome via the {@link ChosenBlock} callbacks.
   *
   * @return {@code true} if {@code send(...)} may block; {@code false} if it returns promptly
   */
  boolean sendIsBlocking();
}
