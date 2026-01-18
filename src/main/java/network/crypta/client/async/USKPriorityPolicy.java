package network.crypta.client.async;

import network.crypta.node.RequestStarter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Computes effective polling priority classes for USK fetchers.
 *
 * <p>This policy aggregates priority hints from subscriber callbacks and fetcher-level callbacks to
 * determine the priority classes used by {@link USKAttemptManager} when scheduling background
 * polls. Callers typically invoke {@link #updatePriorities(USKCallback[], USKFetcherCallback[],
 * String)} whenever callback sets change so that the current polling priorities reflect the most
 * urgent subscriber. The policy maintains the derived priorities as mutable state and exposes them
 * through lightweight accessors.
 *
 * <p>The policy favors the minimum (highest urgency) priority class among all callbacks. When no
 * callbacks are present, it resets to default normal and progress priorities. Instances are not
 * thread-safe; callers should synchronize externally or confine usage to a single scheduling
 * thread. The logic is intentionally conservative to avoid oscillation and uses the existing
 * scheduler constants without performing any blocking work.
 *
 * <ul>
 *   <li>Tracks current normal and progress polling priority classes.
 *   <li>Resets priorities to defaults when no callbacks are registered.
 *   <li>Triggers poll parameter reloads after any effective change.
 * </ul>
 */
final class USKPriorityPolicy {
  /** Logger for priority updates and trace diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(USKPriorityPolicy.class);

  /** Default polling priority for normal background checks. */
  private static final short DEFAULT_NORMAL_POLL_PRIORITY = RequestStarter.PREFETCH_PRIORITY_CLASS;

  /** Default polling priority for progress-oriented checks. */
  private static final short DEFAULT_PROGRESS_POLL_PRIORITY = RequestStarter.UPDATE_PRIORITY_CLASS;

  /** Current polling priority for normal background checks. */
  private short normalPollPriority = DEFAULT_NORMAL_POLL_PRIORITY;

  /** Current polling priority for progress-oriented checks. */
  private short progressPollPriority = DEFAULT_PROGRESS_POLL_PRIORITY;

  /** Attempt manager that consumes polling priorities. */
  private final USKAttemptManager attempts;

  /**
   * Creates a priority policy bound to a specific attempt manager.
   *
   * <p>The manager reference is used to reload polling parameters whenever derived priorities
   * change. The policy does not take ownership of the manager and assumes its lifecycle matches
   * that of the owning fetcher.
   *
   * @param attempts attempt manager that should be updated after priority changes; must be non-null
   */
  USKPriorityPolicy(USKAttemptManager attempts) {
    this.attempts = attempts;
  }

  /**
   * Returns the current normal polling priority class.
   *
   * <p>The value reflects the minimum priority requested by all callbacks or the default priority
   * when no callbacks are present.
   *
   * @return priority class used for steady-state background polling
   */
  short normalPriority() {
    return normalPollPriority;
  }

  /**
   * Returns the current progress polling priority class.
   *
   * <p>The value reflects the minimum progress priority requested by callbacks, which can be more
   * urgent than the normal priority when fast progress is desired.
   *
   * @return priority class used when progress-oriented polling is needed
   */
  short progressPriority() {
    return progressPollPriority;
  }

  /**
   * Recomputes polling priorities based on the active callback sets.
   *
   * <p>The method aggregates the minimum normal and progress priorities across subscriber and
   * fetcher callbacks. If no callbacks are present, it falls back to default priorities. After
   * updating the derived priorities, it triggers a reload of poll parameters so that ongoing
   * attempts adopt the new scheduling classes. The method is deterministic and idempotent for the
   * same input arrays.
   *
   * @param subscribers subscriber callbacks providing polling priority preferences; must not be
   *     null but may be empty
   * @param fetcherCallbacks fetcher callbacks providing polling priority preferences; must not be
   *     null but may be empty
   * @param fetcherName human-readable identifier used only for debug logging
   */
  void updatePriorities(
      USKCallback[] subscribers, USKFetcherCallback[] fetcherCallbacks, String fetcherName) {
    Prio prio = initialPrio();
    if (noCallbacks(subscribers, fetcherCallbacks)) {
      setDefaultPriorities(fetcherName);
      return;
    }

    accumulatePriorities(subscribers, prio);
    accumulatePriorities(fetcherCallbacks, prio);

    if (LOG.isDebugEnabled())
      LOG.debug(
          "Updating priorities: normal={} progress={} for {}",
          prio.normal,
          prio.progress,
          fetcherName);
    normalPollPriority = prio.normal;
    progressPollPriority = prio.progress;
    attempts.reloadPollParameters();
  }

  /**
   * Resets polling priorities to the default values and reloads poll parameters.
   *
   * <p>This is used when no callbacks provide priority hints. It restores normal and progress
   * priorities to their configured defaults and then refreshes the attempt manager's scheduling
   * parameters.
   *
   * @param fetcherName human-readable identifier used only for debug logging
   */
  private void setDefaultPriorities(String fetcherName) {
    normalPollPriority = DEFAULT_NORMAL_POLL_PRIORITY;
    progressPollPriority = DEFAULT_PROGRESS_POLL_PRIORITY;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Updating priorities: normal = {} progress = {} for {}",
          normalPollPriority,
          progressPollPriority,
          fetcherName);
    attempts.reloadPollParameters();
  }

  /** Mutable container for derived polling priorities. */
  private static final class Prio {
    /** Normal polling priority class. */
    short normal;

    /** Progress polling priority class. */
    short progress;

    /** Creates a priority container with unset values. */
    Prio() {}
  }

  /**
   * Creates a priority container initialized to the paused priority class.
   *
   * @return a new priority container with paused defaults
   */
  private static Prio initialPrio() {
    Prio p = new Prio();
    p.normal = RequestStarter.PAUSED_PRIORITY_CLASS;
    p.progress = RequestStarter.PAUSED_PRIORITY_CLASS;
    return p;
  }

  /**
   * Checks whether there are no callbacks influencing priority selection.
   *
   * @param localCallbacks subscriber callbacks to test
   * @param fetcherCallbacks fetcher-level callbacks to test
   * @return {@code true} when both callback arrays are empty
   */
  private static boolean noCallbacks(
      USKCallback[] localCallbacks, USKFetcherCallback[] fetcherCallbacks) {
    return localCallbacks.length == 0 && fetcherCallbacks.length == 0;
  }

  /**
   * Accumulates priority preferences from subscriber callbacks.
   *
   * @param cbs callbacks providing priority hints; must not be null
   * @param prio mutable container to update with minimum priorities
   */
  private static void accumulatePriorities(USKCallback[] cbs, Prio prio) {
    for (USKCallback cb : cbs) {
      short n = cb.getPollingPriorityNormal();
      if (LOG.isTraceEnabled()) LOG.trace("Normal priority for {} : {}", cb, n);
      if (n < prio.normal) prio.normal = n;
      if (LOG.isTraceEnabled()) LOG.trace("Progress priority for {} : {}", cb, n);
      short p = cb.getPollingPriorityProgress();
      if (p < prio.progress) prio.progress = p;
    }
  }

  /**
   * Accumulates priority preferences from fetcher-level callbacks.
   *
   * @param cbs callbacks providing priority hints; must not be null
   * @param prio mutable container to update with minimum priorities
   */
  private static void accumulatePriorities(USKFetcherCallback[] cbs, Prio prio) {
    for (USKFetcherCallback cb : cbs) {
      short n = cb.getPollingPriorityNormal();
      if (LOG.isTraceEnabled()) LOG.trace("Normal priority for {} : {}", cb, n);
      if (n < prio.normal) prio.normal = n;
      if (LOG.isTraceEnabled()) LOG.trace("Progress priority for {} : {}", cb, n);
      short p = cb.getPollingPriorityProgress();
      if (p < prio.progress) prio.progress = p;
    }
  }
}
