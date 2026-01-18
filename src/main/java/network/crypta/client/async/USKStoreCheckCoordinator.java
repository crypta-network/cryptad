package network.crypta.client.async;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import network.crypta.client.FetchContext;
import network.crypta.keys.Key;
import network.crypta.keys.USK;
import network.crypta.node.SendableGet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Coordinates datastore checking and store-check request lifecycle for USK polling. */
final class USKStoreCheckCoordinator {
  private static final Logger LOG = LoggerFactory.getLogger(USKStoreCheckCoordinator.class);

  /** Active store checker getter, or {@code null} when no store scan is running. */
  private USKStoreCheckerGetter runningStoreChecker;

  private final USKKeyWatchSet watchingKeys;
  private final USKAttemptManager attempts;
  private final ClientRequester parent;
  private final boolean checkStoreOnly;
  private final USKManager uskManager;
  private final USK origUSK;
  private final USKStoreCheckCallbacks callbacks;
  private final boolean realTimeFlag;

  static final class Params {
    private final USKKeyWatchSet watchingKeys;
    private final USKAttemptManager attempts;
    private final ClientRequester parent;
    private final boolean checkStoreOnly;
    private final USKManager uskManager;
    private final USK origUSK;
    private final USKStoreCheckCallbacks callbacks;
    private final boolean realTimeFlag;

    private Params(Builder builder) {
      this.watchingKeys = builder.watchingKeys;
      this.attempts = builder.attempts;
      this.parent = builder.parent;
      this.checkStoreOnly = builder.checkStoreOnly;
      this.uskManager = builder.uskManager;
      this.origUSK = builder.origUSK;
      this.callbacks = builder.callbacks;
      this.realTimeFlag = builder.realTimeFlag;
    }

    static Builder builder() {
      return new Builder();
    }

    static final class Builder {
      private USKKeyWatchSet watchingKeys;
      private USKAttemptManager attempts;
      private ClientRequester parent;
      private boolean checkStoreOnly;
      private USKManager uskManager;
      private USK origUSK;
      private USKStoreCheckCallbacks callbacks;
      private boolean realTimeFlag;

      Builder watchingKeys(USKKeyWatchSet watchingKeys) {
        this.watchingKeys = watchingKeys;
        return this;
      }

      Builder attempts(USKAttemptManager attempts) {
        this.attempts = attempts;
        return this;
      }

      Builder parent(ClientRequester parent) {
        this.parent = parent;
        return this;
      }

      Builder checkStoreOnly(boolean checkStoreOnly) {
        this.checkStoreOnly = checkStoreOnly;
        return this;
      }

      Builder uskManager(USKManager uskManager) {
        this.uskManager = uskManager;
        return this;
      }

      Builder origUSK(USK origUSK) {
        this.origUSK = origUSK;
        return this;
      }

      Builder callbacks(USKStoreCheckCallbacks callbacks) {
        this.callbacks = callbacks;
        return this;
      }

      Builder realTimeFlag(boolean realTimeFlag) {
        this.realTimeFlag = realTimeFlag;
        return this;
      }

      Params build() {
        return new Params(this);
      }
    }
  }

  USKStoreCheckCoordinator(Params params) {
    this.watchingKeys = params.watchingKeys;
    this.attempts = params.attempts;
    this.parent = params.parent;
    this.checkStoreOnly = params.checkStoreOnly;
    this.uskManager = params.uskManager;
    this.origUSK = params.origUSK;
    this.callbacks = params.callbacks;
    this.realTimeFlag = params.realTimeFlag;
  }

  /**
   * Starts or continues datastore checking for watched keys.
   *
   * @param ed latest known edition used to seed datastore checks
   * @param context client context used to register the store checker; must not be null
   * @return {@code true} when a store check is already running or was started; {@code false} when
   *     no store check is required
   */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  boolean fillKeysWatching(long ed, ClientContext context) {
    synchronized (this) {
      // Do not run a new one until this one has finished.
      // USKStoreCheckerGetter itself will automatically call back to fillKeysWatching so there is
      // no
      // chance of losing it.
      if (runningStoreChecker != null) return true;
      USKStoreChecker checker = buildStoreChecker(ed);
      if (checker == null) {
        if (LOG.isDebugEnabled()) LOG.debug("No datastore checker");
        return false;
      }

      runningStoreChecker = new USKStoreCheckerGetter(this, callbacks, parent, checker);
    }
    try {
      context
          .getSskFetchScheduler(realTimeFlag)
          .register(null, new SendableGet[] {runningStoreChecker}, false, null, false);
    } catch (Exception t) {
      synchronized (this) {
        runningStoreChecker = null;
      }
      LOG.error("Unable to start: {}", t, t);
      try {
        runningStoreChecker.unregister(context, runningStoreChecker.getPriorityClass());
      } catch (Exception _) {
        // Ignore, hopefully it's already unregistered
      }
    }
    if (LOG.isDebugEnabled()) LOG.debug("Registered {} for {}", runningStoreChecker, callbacks);
    return true;
  }

  /**
   * Completes registration after a datastore checker finishes its pre-registration phase.
   *
   * <p>The method unregisters the checker, marks it complete, then schedules any pending attempts
   * based on the datastore results. When running in store-only mode, it may immediately conclude
   * the round after DBR handling.
   *
   * @param storeChecker active store checker getter instance; must not be null
   * @param checker datastore checker wrapper used to mark completion; must not be null
   * @param context client context used for scheduling and callbacks; must not be null
   * @param toNetwork whether the scheduler intended a network send for the checker
   * @return {@code toNetwork} to preserve scheduler semantics; never sends network requests here
   */
  @SuppressWarnings("java:S3516")
  boolean preRegisterStoreChecker(
      USKStoreCheckerGetter storeChecker,
      USKStoreChecker checker,
      ClientContext context,
      boolean toNetwork) {
    if (callbacks.isCancelled()) {
      storeChecker.unregister(context, storeChecker.getPriorityClass());
      synchronized (this) {
        runningStoreChecker = null;
      }
      if (LOG.isDebugEnabled())
        LOG.debug("StoreChecker preRegister aborted: fetcher cancelled/completed");
      return toNetwork; // cancel network send when scheduler planned to send
      // value ignored by scheduler when toNetwork == false
    }

    storeChecker.unregister(context, storeChecker.getPriorityClass());

    USKAttempt[] attemptsToStart;
    synchronized (this) {
      runningStoreChecker = null;
      // Note: optionally start USKAttempts only when datastore check shows no progress.
      attemptsToStart = attempts.snapshotAttemptsToStart();
      attempts.clearAttemptsToStart();
      if (callbacks.isCancelled()) attemptsToStart = new USKAttempt[0];
    }

    checker.checked();

    if (LOG.isDebugEnabled())
      LOG.debug(
          "Checked datastore, finishing registration for {} checkers for {}",
          attemptsToStart.length,
          origUSK);

    if (attemptsToStart.length > 0) {
      parent.toNetwork(context);
      callbacks.notifySendingToNetwork(context);
    }

    callbacks.processAttemptsAfterStoreCheck(attemptsToStart, context);

    long lastEd = uskManager.lookupLatestSlot(origUSK);
    if (!fillKeysWatching(lastEd, context) && checkStoreOnly) {
      if (LOG.isDebugEnabled()) LOG.debug("Just checking store, terminating {} ...", callbacks);
      if (callbacks.shouldDeferUntilDBRs()) {
        callbacks.setScheduleAfterDBRsDone(true);
      } else {
        callbacks.finishSuccess(context);
      }
    }

    return toNetwork; // Store checker never sends network requests itself
    // Value is ignored when toNetwork == false
  }

  boolean isStoreCheckRunning() {
    synchronized (this) {
      return runningStoreChecker != null;
    }
  }

  void cancelStoreChecker(ClientContext context) {
    USKStoreCheckerGetter checker;
    synchronized (this) {
      checker = runningStoreChecker;
      runningStoreChecker = null;
    }
    if (checker != null) {
      checker.unregister(context, checker.getPriorityClass());
    }
  }

  private USKStoreChecker buildStoreChecker(long ed) {
    List<USKKeyWatchSet.KeyList.StoreSubChecker> checkers = watchingKeys.getDatastoreCheckers(ed);
    if (checkers == null) return null;
    return new USKStoreChecker(checkers);
  }

  /**
   * Bundles datastore sub-checkers used to query the local store for candidate editions.
   *
   * <p>This helper merges keys from multiple sources and forwards completion notifications back to
   * the underlying sub-checkers.
   */
  final class USKStoreChecker {

    /** Sub-checkers contributing keys to query in the datastore. */
    final USKKeyWatchSet.KeyList.StoreSubChecker[] checkers;

    /**
     * Creates a store checker from a list of sub-checkers.
     *
     * @param c sub-checkers that contribute keys; must not be null
     */
    public USKStoreChecker(List<USKKeyWatchSet.KeyList.StoreSubChecker> c) {
      checkers = c.toArray(new USKKeyWatchSet.KeyList.StoreSubChecker[0]);
    }

    /**
     * Creates a store checker from an array of sub-checkers.
     *
     * @param checkers2 sub-checker array to use directly; must not be null
     */
    @SuppressWarnings("unused")
    public USKStoreChecker(USKKeyWatchSet.KeyList.StoreSubChecker[] checkers2) {
      checkers = checkers2;
    }

    /**
     * Returns the merged list of keys to check in the datastore.
     *
     * @return array of keys to check; may be empty
     */
    public Key[] getKeys() {
      if (checkers.length == 0) return new Key[0];
      if (checkers.length == 1) return checkers[0].keysToCheck;
      return mergeKeysFromCheckers();
    }

    /**
     * Merges keys from all sub-checkers into a de-duplicated array.
     *
     * @return merged array of keys to check in the datastore
     */
    private Key[] mergeKeysFromCheckers() {
      int x = 0;
      for (USKKeyWatchSet.KeyList.StoreSubChecker checker : checkers) {
        x += checker.keysToCheck.length;
      }
      Key[] keys = new Key[x];
      int ptr = 0;
      // Note: a more efficient merging algorithm could consider ranges.
      HashSet<Key> check = new HashSet<>();
      for (USKKeyWatchSet.KeyList.StoreSubChecker checker : checkers) {
        for (Key k : checker.keysToCheck) {
          if (!check.add(k)) continue;
          keys[ptr++] = k;
        }
      }
      if (keys.length != ptr) {
        keys = Arrays.copyOf(keys, ptr);
      }
      return keys;
    }

    /** Notifies all sub-checkers that their datastore checks have completed. */
    public void checked() {
      for (USKKeyWatchSet.KeyList.StoreSubChecker checker : checkers) {
        checker.checked();
      }
    }
  }

  interface USKStoreCheckCallbacks {
    void finishSuccess(ClientContext context);

    void notifySendingToNetwork(ClientContext context);

    void processAttemptsAfterStoreCheck(USKAttempt[] attempts, ClientContext context);

    boolean shouldDeferUntilDBRs();

    void setScheduleAfterDBRsDone(boolean value);

    boolean isCancelled();

    FetchContext fetcherContext();

    USKFetcher fetcher();
  }
}
