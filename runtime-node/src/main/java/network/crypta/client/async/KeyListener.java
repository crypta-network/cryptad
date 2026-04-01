package network.crypta.client.async;

import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.node.SendableGet;

/**
 * Listener that screens and optionally consumes keys fetched by the node.
 *
 * <p>A {@code KeyListener} is a transient, lightweight object attached to a higher-level client
 * request in order to monitor the stream of successfully fetched keys and quickly decide whether a
 * given key is relevant. It is created on startup for persistent requests or on demand for
 * ephemeral ones. Implementations typically use one or more Bloom filters to provide a near-O(1)
 * rejection path in {@link #probablyWantKey(Key, byte[])}, followed by a definitive decision in
 * {@link #definitelyWantKey(Key, byte[], ClientContext)} and eventual processing via {@link
 * #handleBlock(Key, byte[], KeyBlock, ClientContext)}. Expensive work is deferred to the
 * appropriate background thread(s) supplied by the {@link ClientContext}.
 *
 * <p>Concurrency and locking: fast-path methods may be invoked while holding internal scheduler
 * locks. Implementations should avoid external locking and blocking I/O inside these paths. The
 * listener is short-lived and should not retain large state; long-lived ownership remains with the
 * parent {@link HasKeyListener}. The {@code saltedKey} argument is the globally salted routing key
 * (concatenate a global salt and then hash) supplied to eliminate re-computation in the hot path.
 * Some implementations also apply a secondary, local salt when using multiple Bloom filters.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> quickly filter candidates, confirm interest, and handle
 *       matching blocks.
 *   <li><strong>Typical usage:</strong> obtain from {@link HasKeyListener}, call {@link
 *       #probablyWantKey(Key, byte[])}, then either escalate to {@link #definitelyWantKey(Key,
 *       byte[], ClientContext)} or directly to {@link #handleBlock(Key, byte[], KeyBlock,
 *       ClientContext)} depending on the caller.
 *   <li><strong>Lifecycle:</strong> the listener may be deactivated at any time via {@link
 *       #onRemove()} or when {@link #isEmpty()} becomes {@code true}.
 * </ul>
 *
 * @author Matthew Toseland {@literal <toad@amphibian.dyndns.org>} (0xE43DA450)
 * @see HasKeyListener
 * @see KeyListenerTracker
 * @see ClientContext
 * @see SendableGet
 */
public interface KeyListener {

  /**
   * Make a fast, approximate decision about whether the key is of interest.
   *
   * <p>This method is expected to be extremely cheap and is commonly backed by one or more Bloom
   * filters. Callers may execute it while holding internal scheduler locks, therefore
   * implementations should avoid external synchronization and any blocking operations. The {@code
   * saltedKey} is the globally salted routing key provided by the caller to avoid repeated hashing
   * in hot paths.
   *
   * @param key the candidate key object as received from the fetch pipeline; never {@code null}
   * @param saltedKey the globally salted routing key bytes for {@code key}; the buffer is read-only
   *     to the callee and must not be retained or modified
   * @return {@code true} when the listener likely wants the key (subject to false positives);
   *     {@code false} when the key is definitely not relevant to this listener
   */
  boolean probablyWantKey(Key key, byte[] saltedKey);

  /**
   * Confirm interest in the key and return the associated request priority.
   *
   * <p>Unlike {@link #probablyWantKey(Key, byte[])}, this method is consulted before initiating
   * work that may be expensive (e.g., scheduling fetch attempts or decoding). It must produce a
   * stable answer for the current state. Implementations should remain fast and avoid external
   * locking. A negative return value signals that the listener is not interested.
   *
   * @param key the candidate key to confirm; same object previously screened by {@link
   *     #probablyWantKey(Key, byte[])}
   * @param saltedKey the globally salted routing key corresponding to {@code key}; provided for
   *     reuse and not for retention or mutation by the callee
   * @param context execution context for client operations; provides schedulers and shared services
   *     required for deeper checks
   * @return the priority class of the interested request when the key is desired; {@code -1} when
   *     the key is not wanted by this listener
   */
  short definitelyWantKey(Key key, byte[] saltedKey, ClientContext context);

  /**
   * Return the concrete requests associated with the specified key, if any.
   *
   * <p>This hook is used by retry/cooldown logic to map a key back to one or more concrete {@link
   * SendableGet} instances. Callers should first filter using {@link #probablyWantKey(Key,
   * byte[])}. Implementations may return {@code null} when unused by a specific listener type.
   *
   * @param key the candidate key under consideration; never {@code null}
   * @param saltedKey the globally salted routing key bytes for {@code key}; read-only to the callee
   * @param context execution context supplying shared services and schedulers
   * @return an array of {@link SendableGet} requests related to {@code key}, or {@code null} when
   *     not applicable or when no requests are currently linked
   */
  SendableGet[] getRequestsForKey(Key key, byte[] saltedKey, ClientContext context);

  /**
   * Consume a fetched block when the key is confirmed to be relevant.
   *
   * <p>Callers should only invoke this after a positive decision from {@link #probablyWantKey(Key,
   * byte[])} (and optionally {@link #definitelyWantKey(Key, byte[], ClientContext)}).
   * Implementations decode/validate the {@link KeyBlock} and update any associated request state.
   * The method should avoid expensive operations on hot-path threads; heavy work should be
   * delegated to background components from {@code context}.
   *
   * @param key the key that produced the block; never {@code null}
   * @param saltedKey the globally salted routing key for {@code key}; provided for fast removal
   *     from filters and similar structures
   * @param found the successfully fetched block corresponding to {@code key}; must be treated as
   *     read-only by the listener
   * @param context execution context with facilities for scheduling and persistence interactions
   * @return {@code true} when the block was recognized and processed by this listener; {@code
   *     false} when it was ignored (e.g., a false positive or non-matching segment)
   */
  boolean handleBlock(Key key, byte[] saltedKey, KeyBlock found, ClientContext context);

  /**
   * Report whether this listener belongs to a persistent request.
   *
   * <p>Persistent requests are restored across restarts and may retain lightweight state for the
   * duration. Callers can use this signal to decide when to write metadata and how aggressively to
   * reuse listeners during startup.
   *
   * @return {@code true} when the owning request is persistent and may outlive the current process
   *     session; {@code false} for transient/ephemeral requests
   */
  boolean persistent();

  /**
   * Return the priority class associated with the owning request.
   *
   * <p>Callers may invoke this inside internal locks; implementations should avoid external
   * synchronization. The priority value is used by schedulers to order work relative to other
   * requests.
   *
   * @return the priority class value that should be used when scheduling related work
   */
  short getPriorityClass();

  /**
   * Count the number of keys that remain of interest to this listener.
   *
   * <p>Implementations for persistent fetches may report the number of outstanding keys. Some
   * ephemeral listeners can return trivial values. The result is advisory and intended for metrics
   * and housekeeping only.
   *
   * @return a non-negative count of remaining candidate or outstanding keys tracked by the listener
   */
  long countKeys();

  /**
   * Return the factory/owner that produced this listener.
   *
   * <p>The owner remains active while the listener is attached, which implies it may be retained in
   * memory. Owners can be deactivated independently, in which case callers should stop invoking the
   * listener.
   *
   * @return the non-{@code null} {@link HasKeyListener} that created and owns this listener
   */
  HasKeyListener getHasKeyListener();

  /**
   * Notification that the listener is being removed from tracking structures.
   *
   * <p>Implementations should promptly release transient state and mark themselves inactive. No
   * further callbacks are guaranteed after this point.
   */
  void onRemove();

  /**
   * Indicate whether the listener has no further work to perform.
   *
   * <p>Return {@code true} when all required keys have been found or when sufficient progress has
   * been made for the owning request to be considered complete. Callers may use this to remove the
   * listener from internal registries.
   *
   * @return {@code true} when no keys remain of interest; {@code false} otherwise
   */
  boolean isEmpty();

  /**
   * Report whether this listener exclusively targets SSK-style keys.
   *
   * <p>This is a convenience flag for callers that need to distinguish between key families, for
   * example to interpret {@link #getWantedKey()} correctly.
   *
   * @return {@code true} when this listener concerns SSK keys; {@code false} otherwise
   */
  boolean isSSK();

  /**
   * Optionally expose the single key identifier this listener is interested in.
   *
   * <p>When non-{@code null}, the returned value identifies the only key of interest using one of
   * two encodings: if {@link #isSSK()} is {@code true}, the value is the public-key hash; otherwise
   * it is the routing key. The value must be consistent with {@link HasKeyListener#getWantedKey()}
   * for the owning request.
   *
   * @return a non-{@code null} byte array when exactly one key is targeted, or {@code null} when
   *     the listener matches multiple keys. Callers must treat the returned buffer as immutable.
   */
  byte[] getWantedKey();
}
