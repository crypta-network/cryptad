package network.crypta.runtime.spi;

import java.util.List;

/**
 * Queue-mutation capability for existing persistent requests exposed through the runtime SPI.
 *
 * <p>This port keeps the remaining queue-administration mutations behind the JDK-only runtime
 * boundary while leaving request parsing, confirmation pages, redirects, and HTTP-specific error
 * mapping in the caller. The surface is intentionally narrow: it covers only mutations for
 * already-existing persistent requests and does not model request creation, queue rendering, or
 * daemon-specific queue item types.
 *
 * <p>Callers should pass already-validated identifiers in the order they want them processed. The
 * port preserves the legacy daemon semantics for remove, restart, priority changes, and bulk
 * cleanup of finished uploads or downloads.
 *
 * <p>Typical callers are HTTP or command-processing layers that have already decided which queue
 * items to act on and how to map failures back to user-facing responses. Implementations may be
 * backed by a live daemon, a test double, or a future non-daemon runtime, but they should keep this
 * contract stable: methods act only on existing persistent requests, perform work in the supplied
 * identifier order when identifiers are provided, and report persistence-unavailable conditions
 * through {@link RequestQueueUnavailableException}.
 *
 * <ul>
 *   <li>Request parsing and validation stay outside this port.
 *   <li>Queue rendering and request creation stay outside this port.
 *   <li>Implementations preserve the legacy persistent-queue semantics for these mutations.
 * </ul>
 *
 * @see QueuePagePort
 */
public interface QueueMutationPort {
  /**
   * Removes the persistent requests identified by the supplied identifiers.
   *
   * <p>Callers should pass identifiers that already correspond to existing persistent requests.
   * Implementations process the list in the supplied order and may stop at the first failure, so
   * callers should not assume all identifiers were removed when an exception is thrown.
   *
   * @param identifiers request identifiers to remove from the persistent queue in caller order
   * @throws RequestQueueUnavailableException if the persistent queue cannot accept mutation
   */
  void removeRequests(List<String> identifiers) throws RequestQueueUnavailableException;

  /**
   * Restarts the persistent requests identified by the supplied identifiers.
   *
   * <p>This operation is intended for existing persistent requests that should be re-run with the
   * daemon's legacy restart semantics. The {@code disableFilterData} flag is passed through without
   * reinterpretation so the caller remains responsible for choosing the correct restart behavior
   * for the current request flow.
   *
   * @param identifiers request identifiers to restart in the order selected by the caller
   * @param disableFilterData {@code true} to disable filter-data handling during restart
   * @throws RequestQueueUnavailableException if the persistent queue cannot perform the restart
   */
  void restartRequests(List<String> identifiers, boolean disableFilterData)
      throws RequestQueueUnavailableException;

  /**
   * Changes the priority class of the persistent requests identified by the supplied identifiers.
   *
   * <p>This method updates only already-existing persistent requests. The numeric priority class is
   * the legacy queue value expected by the backing runtime, so callers should validate or derive it
   * before invoking the port rather than expecting the implementation to translate user-facing
   * labels.
   *
   * @param identifiers request identifiers whose priority should be updated in caller order
   * @param newPriorityClass legacy queue priority class to assign to every selected request
   * @throws RequestQueueUnavailableException if the persistent queue cannot apply the priority
   *     change
   */
  void changePriority(List<String> identifiers, short newPriorityClass)
      throws RequestQueueUnavailableException;

  /**
   * Removes finished upload requests that match the current legacy cleanup semantics.
   *
   * <p>The exact definition of a removable finished upload is implementation-specific but should
   * remain aligned with the daemon's established queue cleanup behavior. Callers use this when they
   * want a bulk cleanup action instead of selecting individual identifiers.
   *
   * @throws RequestQueueUnavailableException if the persistent queue cannot perform upload cleanup
   */
  void removeFinishedUploads() throws RequestQueueUnavailableException;

  /**
   * Removes finished download requests that match the current legacy cleanup semantics.
   *
   * <p>The exact definition of a removable finished download is implementation-specific but should
   * remain aligned with the daemon's established queue cleanup behavior, including any legacy
   * filters around persistence, finalization, or temporary storage.
   *
   * @throws RequestQueueUnavailableException if the persistent queue cannot perform download
   *     cleanup
   */
  void removeFinishedDownloads() throws RequestQueueUnavailableException;
}
