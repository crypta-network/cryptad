package network.crypta.client.async;

import network.crypta.node.RequestStarter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Handles polling priority calculations for USK fetchers. */
final class USKPriorityPolicy {
  private static final Logger LOG = LoggerFactory.getLogger(USKPriorityPolicy.class);

  /** Default polling priority for normal background checks. */
  private static final short DEFAULT_NORMAL_POLL_PRIORITY = RequestStarter.PREFETCH_PRIORITY_CLASS;

  /** Default polling priority for progress-oriented checks. */
  private static final short DEFAULT_PROGRESS_POLL_PRIORITY = RequestStarter.UPDATE_PRIORITY_CLASS;

  /** Current polling priority for normal background checks. */
  private short normalPollPriority = DEFAULT_NORMAL_POLL_PRIORITY;

  /** Current polling priority for progress-oriented checks. */
  private short progressPollPriority = DEFAULT_PROGRESS_POLL_PRIORITY;

  private final USKAttemptManager attempts;

  USKPriorityPolicy(USKAttemptManager attempts) {
    this.attempts = attempts;
  }

  short normalPriority() {
    return normalPollPriority;
  }

  short progressPriority() {
    return progressPollPriority;
  }

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
