package network.crypta.runtime.spi;

import java.io.IOException;

/**
 * Exposes the remaining queue support hooks still needed by the HTTP layer.
 *
 * <p>This SPI is intentionally narrow and transitional. The queue toadlets still have a small
 * support-oriented slice that must preserve existing behavior while the daemon continues to own the
 * real queue backend, persistence lifecycle, and panic mechanics. Instead of letting the HTTP layer
 * reach into the live daemon state directly, callers use this port to ask a few targeted questions
 * and to trigger the existing order-sensitive panic flow.
 *
 * <p>The port is not a general queue-management API. Queue reads, queue creation, completed-list
 * tracking, and existing-request mutations stay on their dedicated ports. Implementations may still
 * consult live daemon objects internally, but callers should only rely on the detached contract
 * defined here.
 *
 * <ul>
 *   <li>Availability gating for the queue backend.
 *   <li>Point-in-time persistence support state for queue error pages.
 *   <li>Start and finish hooks for the legacy panic workflow.
 * </ul>
 *
 * @see QueuePersistenceStatusSnapshot
 */
public interface QueueSupportPort {
  /**
   * Returns whether the queue backend is currently enabled.
   *
   * <p>Callers use this to preserve the existing "please enable FCP" gate without depending on
   * daemon-local FCP types or daemon-global singletons. The result is a live availability check,
   * not a configuration snapshot, so implementations may consult the current daemon state each time
   * the queue page is rendered.
   *
   * @return {@code true} when the live queue backend is enabled
   */
  boolean isQueueBackendEnabled();

  /**
   * Returns the current detached persistence-support status for the queue pages.
   *
   * <p>The returned snapshot preserves the legacy queue-page support branches: awaiting-password,
   * shutting-down, and persistence-broken rendering. Implementations may leave the persistence path
   * fields empty for the awaiting-password and shutting-down branches because those values are only
   * rendered on the persistence-broken page. Callers should treat the snapshot as a detached state
   * for one response rather than a live object that stays in sync with daemon transitions.
   *
   * @return current queue-persistence status snapshot
   */
  QueuePersistenceStatusSnapshot persistenceStatus();

  /**
   * Starts the legacy panic sequence.
   *
   * <p>Callers should preserve the existing order-sensitive flow: invoke this method, render the
   * panicking page, then call {@link #finishPanic()}. Implementations may perform irreversible
   * daemon-side work here, so callers should not treat the method as idempotent or retry-safe
   * unless a specific implementation documents stronger guarantees.
   *
   * @throws IOException if the daemon's panic-start sequence fails while deleting the master keys
   *     file
   */
  void beginPanic() throws IOException;

  /**
   * Completes the legacy panic sequence after the panicking page has been rendered.
   *
   * <p>This second step lets the HTTP layer preserve the historic user-visible ordering while the
   * daemon keeps ownership of the underlying shutdown and cleanup mechanics.
   */
  void finishPanic();
}
