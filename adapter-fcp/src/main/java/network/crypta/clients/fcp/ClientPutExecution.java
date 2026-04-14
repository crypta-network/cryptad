package network.crypta.clients.fcp;

import java.io.Serializable;
import network.crypta.client.InsertException;
import network.crypta.client.async.ClientRequester;

/**
 * Opaque adapter-owned handle for one live single-file insert execution.
 *
 * <p>The adapter treats this as the boundary object for a request attempt. The bridge module owns
 * the concrete daemon inserter and exposes only the lifecycle and observation operations that the
 * FCP request classes need. A {@code ClientPutExecution} instance represents one live insert
 * attempt for a {@link ClientPut}: callers can inspect the low-level requester for status and
 * priority propagation, start the execution once the request has been registered, and ask the
 * bridge to restart the insert when the underlying runtime object still retains enough states to do
 * so.
 *
 * <p>The interface is intentionally small and serializable. Persistent request objects may keep a
 * handle across node restarts, but the concrete runtime-owned requester still lives entirely behind
 * the bridge boundary. That allows the FCP adapter to preserve request lifecycle behavior without
 * compiling directly against the daemon insert-engine implementation classes.
 */
public interface ClientPutExecution extends Serializable {

  /**
   * Returns the low-level requester backing this execution.
   *
   * <p>The adapter uses the requester for generic request bookkeeping such as diagnostics, cache
   * updates, and priority changes. Callers should treat the returned object as a bridge-owned live
   * state and should not assume that its concrete type is stable across implementations.
   *
   * @return live requester that currently backs this insert execution
   */
  ClientRequester requester();

  /**
   * Starts the live insert execution in the supplied client context.
   *
   * <p>This is the normal transition from a constructed FCP request into an actively running
   * insert. Implementations should schedule the underlying work promptly and report any immediate
   * start-up validation failures through the declared exception.
   *
   * @param context live client context that provides schedulers, randomness, and persistence hooks
   * @throws InsertException if the insert cannot be started with the supplied runtime state
   */
  void start(network.crypta.client.async.ClientContext context) throws InsertException;

  /**
   * Returns whether the current execution can be restarted.
   *
   * <p>This reports whether the underlying runtime object still has enough retained states for a
   * restart attempt to succeed. The adapter uses it to decide whether a finished failed request
   * should offer a retry path.
   *
   * @return {@code true} when a later call to {@link
   *     #restart(network.crypta.client.async.ClientContext)} may succeed
   */
  boolean canRestart();

  /**
   * Restarts the live insert execution in the supplied client context.
   *
   * <p>Implementations may either reuse the retained runtime state or rebuild a new runtime-owned
   * inserter behind the seam. Callers expect the restart to preserve the user-visible FCP request
   * semantics for the surrounding {@link ClientPut}.
   *
   * @param context live client context to use for the restart attempt
   * @return {@code true} when the restart was scheduled successfully
   * @throws InsertException if the restart cannot be scheduled
   */
  boolean restart(network.crypta.client.async.ClientContext context) throws InsertException;

  /**
   * Returns the splitfile crypto key currently associated with this execution, if any.
   *
   * <p>Persistent FCP tags use this value to report the effective splitfile key back to connected
   * clients. Implementations may return {@code null} when no splitfile key is currently available
   * or the active insert mode does not expose one.
   *
   * @return current splitfile crypto key for this execution, or {@code null} when unavailable
   */
  byte[] getSplitfileCryptoKey();
}
