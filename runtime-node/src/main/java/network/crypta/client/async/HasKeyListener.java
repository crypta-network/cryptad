package network.crypta.client.async;

/**
 * Factory interface for producing {@link KeyListener} instances.
 *
 * <p>Implementations represent a higher-level client request that can attach a transient {@link
 * KeyListener} to the node's fetch pipeline. The listener observes the stream of keys that are
 * successfully fetched by the network layer and decides which of them are relevant to the owning
 * request. Typical implementations include single-block fetchers and composite fetchers for split
 * files or update streams. The factory method allows the scheduler to obtain a fresh listener
 * whenever work is (re)registered, and to avoid holding on to long-lived state in the listener
 * itself.
 *
 * <p>Lifecycle and state: the owner may become cancelled or completed at any time; in that case the
 * factory should return {@code null} from {@link #makeKeyListener(ClientContext, boolean)} to
 * signal that no further callbacks are desired. Implementations are generally not thread-safe for
 * mutation without their own synchronization; callers should respect any locking guidance on the
 * returned {@link KeyListener} and avoid external locks inside its fast paths.
 *
 * <ul>
 *   <li>Responsibilities: create lightweight listeners; advertise cancellation; optionally expose a
 *       single "wanted" key.
 *   <li>Concurrency: listeners may be invoked on internal scheduler threads; keep them fast and
 *       non-blocking.
 *   <li>Usage: obtain a listener, feed it candidate keys, and release it once the request finishes
 *       or is cancelled.
 * </ul>
 *
 * @author Matthew Toseland {@literal <toad@amphibian.dyndns.org>} (0xE43DA450)
 * @see KeyListener
 * @see ClientContext
 */
public interface HasKeyListener {

  /**
   * Create a new {@link KeyListener} to screen candidate keys and process any matching blocks.
   *
   * <p>The returned listener is expected to be transient and inexpensive. Callers may invoke it on
   * scheduler or worker threads; implementations should avoid blocking I/O and heavy locking inside
   * the listener's fast-path methods. Returning {@code null} indicates that the owning request has
   * finished or has been cancelled and no listener should be attached.
   *
   * <p>The {@code onStartup} flag is a hint that the listener is being created while restoring
   * persistent state during node startup. Implementations that would otherwise perform eager work
   * can use this to defer non-essential activity until after initialization. The flag does not
   * change call ordering or required semantics.
   *
   * @param context execution context for client operations; provides schedulers and shared
   *     services. Never {@code null}; intended for cheap, read-mostly access during listener
   *     creation.
   * @param onStartup {@code true} when invoked as part of startup/persistence recovery; {@code
   *     false} for normal scheduling or re-registration flows.
   * @return a new listener instance tied to this request, or {@code null} when the request no
   *     longer accepts callbacks (for example, after completion or cancellation). The caller does
   *     not take ownership beyond using it for the current registration window.
   */
  KeyListener makeKeyListener(ClientContext context, boolean onStartup);

  /**
   * Report whether the owning request has been cancelled or otherwise made inactive.
   *
   * <p>Callers use this to short-circuit scheduling and listener creation. Once a request reports
   * cancellation, it is treated as completed for the purpose of key tracking and should no longer
   * emit or handle new events.
   *
   * @return {@code true} when the request should be treated as cancelled or inactive; {@code false}
   *     when it remains eligible to receive callbacks.
   */
  boolean isCancelled();

  /**
   * Optionally expose a single key that this request targets exclusively.
   *
   * <p>When non-{@code null}, the returned byte array identifies the only key that is interesting
   * to this request. For SSK-style keys the value is the public-key hash; for other key types it is
   * the routing key. Returning {@code null} indicates that the request may consider many different
   * keys and cannot be summarized by a single identifier.
   *
   * @return a non-{@code null} identifier for the only key of interest, or {@code null} when the
   *     request matches multiple keys. The array contents must be stable for the lifetime of the
   *     request; callers will not modify the returned buffer.
   */
  byte[] getWantedKey();
}
