package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;

import network.crypta.client.async.ChosenBlock;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestSelector;
import network.crypta.keys.Key;

/**
 * Schedules and coordinates client requests for fetching and inserting data.
 *
 * <p>The scheduler tracks keys that are currently being fetched, selects the next unit of work, and
 * applies cooldown heuristics to avoid repeatedly requesting the same key within a short period.
 * Implementations define the exact policies for prioritization and fairness.
 *
 * <p>Callers should treat the interface as an orchestration boundary between request producers and
 * the worker execution layer. Concurrency guarantees depend on the concrete implementation; callers
 * may invoke methods from multiple threads unless noted otherwise by the implementation.
 */
public interface RequestScheduler {

  /**
   * Records that a {@code get} request has completed successfully.
   *
   * <p>Implementations may schedule additional work from the same selection group (e.g., a
   * RandomGrabArray) under the heuristic that adjacent requests are likely to succeed when one has
   * just succeeded.
   *
   * @param get the completed request instance
   * @param persistent whether the request is persistent (survives restarts)
   */
  void succeeded(BaseSendableGet get, boolean persistent);

  /**
   * Cooldown duration in milliseconds applied after exceeding {@link #COOLDOWN_RETRIES} for a key.
   * Avoids redundant traffic for repeated failures.
   */
  long COOLDOWN_PERIOD = MINUTES.toMillis(30);

  /**
   * Maximum consecutive request attempts for a key before entering cooldown.
   *
   * <p>Clients that must bypass cooldown should configure a maximum retry count lower than this
   * value (and greater than {@code -1}).
   */
  int COOLDOWN_RETRIES = 3;

  /**
   * Returns the number of requests currently queued and not yet running.
   *
   * @return queued request count
   */
  long countQueuedRequests();

  /**
   * Returns the handle that tracks keys being fetched on this node.
   *
   * @return local fetching tracker
   */
  KeysFetchingLocally fetchingKeys();

  /**
   * Removes a key from the local fetching tracker when no longer needed.
   *
   * @param key the key to clear from the fetching set
   */
  void removeFetchingKey(Key key);

  /**
   * Records a failure for a get request and applies policy (e.g., retry or cooldown).
   *
   * @param get the request that failed
   * @param e the failure cause
   * @param prio scheduler priority associated with the request
   * @param persistent whether the request is persistent (survives restarts)
   */
  void callFailure(SendableGet get, LowLevelGetException e, int prio, boolean persistent);

  /**
   * Records a failure for an insert request and applies policy (e.g., retry or cooldown).
   *
   * @param insert the request that failed
   * @param exception the failure cause
   * @param prio scheduler priority associated with the request
   * @param persistent whether the request is persistent (survives restarts)
   */
  void callFailure(
      SendableInsert insert, LowLevelPutException exception, int prio, boolean persistent);

  /**
   * Returns the client context associated with this scheduler.
   *
   * @return client context
   */
  ClientContext getContext();

  /**
   * Adds a key to the set of keys being fetched.
   *
   * @param key the key to begin tracking
   * @return {@code true} if the key was accepted for fetching
   */
  boolean addToFetching(Key key);

  /**
   * Selects the next unit of work to run according to the scheduler's policy.
   *
   * @return the chosen block of work, or {@code null} if none is available
   */
  ChosenBlock grabRequest();

  /**
   * Removes a running request from the scheduler's active set after completion or cancellation.
   *
   * @param request the request to remove from the running set
   */
  @SuppressWarnings("unused")
  void removeRunningRequest(SendableRequest request);

  /**
   * Returns whether a persistent request is currently running or queued.
   *
   * <p>Transient requests are selected at a {@code (SendableRequest, token)} granularity and are
   * therefore not covered by this check.
   */
  boolean isRunningOrQueuedPersistentRequest(SendableRequest request);

  /**
   * Checks whether a key is already being fetched and optionally records a waiter.
   *
   * <p>When {@code getterWaiting} is provided, implementations may remember the waiter to awaken it
   * (for example, via a cooldown queue) when the fetch completes.
   *
   * @param key the key being queried
   * @param getterWaiting optional request to notify when the key completes
   * @param persistent whether the waiter is persistent
   * @return {@code true} if the key is currently being fetched
   */
  @SuppressWarnings("unused")
  boolean hasFetchingKey(Key key, BaseSendableGet getterWaiting, boolean persistent);

  /**
   * Adds an insert request to the running set keyed by a token.
   *
   * @param insert the insert to track
   * @param token the item key that identifies the insert instance
   * @return {@code true} if the insert was added
   */
  boolean addRunningInsert(SendableInsert insert, SendableRequestItemKey token);

  /**
   * Removes an insert request from the running set.
   *
   * @param insert the insert to stop tracking
   * @param token the item key that identifies the insert instance
   */
  void removeRunningInsert(SendableInsert insert, SendableRequestItemKey token);

  /** Wakes any starter thread or mechanism to re-evaluate pending work. */
  void wakeStarter();

  /**
   * Indicates whether the scheduler is interested in requesting the given key at this time.
   *
   * <p>Useful for early filtering (e.g., cooldown, backoff, or policy constraints) before
   * allocating resources to a fetch.
   *
   * @param key the key to evaluate
   * @return {@code true} if the key should be requested
   */
  /* Security note: Clarify trust and authorization boundaries if a future tunneling
   * mechanism allows starting requests remotely. Revisit the caller-side logic noted in
   * RequestHandler (onAbort() handler) to ensure this check remains valid. */
  boolean wantKey(Key key);

  /**
   * Returns the request selector that drives scheduling policy.
   *
   * @return client request selector
   */
  ClientRequestSelector getSelector();
}
