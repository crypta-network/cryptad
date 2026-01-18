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

/**
 * Coordinates datastore checking and store-check request lifecycle for USK polling.
 *
 * <p>This coordinator owns the lifecycle for datastore-only checks that precede or complement
 * polling attempts. It registers store checkers with the scheduler, monitors their completion, and
 * then decides whether to start polling attempts or conclude in store-only mode. The coordinator is
 * constructed with shared dependencies and a callback interface that bridges back into the owning
 * fetcher when scheduling and completion decisions are made.
 *
 * <p>The class is mutable and synchronizes around its running checker state to prevent concurrent
 * registration. Callers generally invoke {@link #fillKeysWatching(long, ClientContext)} and {@link
 * #preRegisterStoreChecker(USKStoreCheckerGetter, USKStoreChecker, ClientContext, boolean)} from
 * scheduler threads. The design favors correctness and safe cancellation over aggressive
 * parallelism; only one store check may run at a time, and callers must respect cancellation flags
 * supplied via {@link USKStoreCheckCallbacks}.
 *
 * <ul>
 *   <li>Registers datastore checkers and tracks whether one is active.
 *   <li>Starts or resumes polling attempts after store checks complete.
 *   <li>Supports store-only rounds that may terminate without network activity.
 * </ul>
 */
final class USKStoreCheckCoordinator {
  /** Logger for store-check lifecycle events and diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(USKStoreCheckCoordinator.class);

  /** Active store checker getter, or {@code null} when no store scan is running. */
  private USKStoreCheckerGetter runningStoreChecker;

  /** Watched key set used to derive datastore checks. */
  private final USKKeyWatchSet watchingKeys;

  /** Attempt manager used to schedule polling attempts after store checks. */
  private final USKAttemptManager attempts;

  /** Parent requester used for scheduling and network accounting. */
  private final ClientRequester parent;

  /** Whether this coordinator should avoid network fetches and only check the store. */
  private final boolean checkStoreOnly;

  /** USK manager used to query the latest known slot. */
  private final USKManager uskManager;

  /** Base USK being checked for datastore availability. */
  private final USK origUSK;

  /** Callback interface used to bridge to the owning fetcher. */
  private final USKStoreCheckCallbacks callbacks;

  /** Whether store checks should run with real-time scheduling bias. */
  private final boolean realTimeFlag;

  /**
   * Parameters used to configure {@link USKStoreCheckCoordinator}.
   *
   * <p>This bundle captures the stable collaborators required to schedule store checks. It is
   * constructed via the nested {@link Builder} to keep constructor signatures small and encourage
   * explicit configuration.
   */
  static final class Params {
    /** Key watch set that supplies datastore checkers. */
    private final USKKeyWatchSet watchingKeys;

    /** Attempt manager that schedules polling attempts after store checks. */
    private final USKAttemptManager attempts;

    /** Parent requester used for network scheduling and priority decisions. */
    private final ClientRequester parent;

    /** Whether the fetcher should perform store-only checks without network activity. */
    private final boolean checkStoreOnly;

    /** Manager used to query the latest known slot values. */
    private final USKManager uskManager;

    /** Base USK that is being checked. */
    private final USK origUSK;

    /** Callback interface used to notify the owning fetcher. */
    private final USKStoreCheckCallbacks callbacks;

    /** Whether store checks should run with real-time bias. */
    private final boolean realTimeFlag;

    /**
     * Creates a parameter bundle from the provided builder.
     *
     * @param builder builder that supplies all required fields
     */
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

    /**
     * Returns a new builder for assembling {@link Params}.
     *
     * @return a fresh builder instance with unset fields
     */
    static Builder builder() {
      return new Builder();
    }

    /**
     * Builder for {@link Params}.
     *
     * <p>Each setter returns the builder to allow chaining. Call {@link #build()} once all fields
     * are configured.
     */
    static final class Builder {
      /** Key watch set that supplies datastore checkers. */
      private USKKeyWatchSet watchingKeys;

      /** Attempt manager that schedules polling attempts after store checks. */
      private USKAttemptManager attempts;

      /** Parent requester used for network scheduling and priority decisions. */
      private ClientRequester parent;

      /** Whether the fetcher should perform store-only checks without network activity. */
      private boolean checkStoreOnly;

      /** Manager used to query the latest known slot values. */
      private USKManager uskManager;

      /** Base USK that is being checked. */
      private USK origUSK;

      /** Callback interface used to notify the owning fetcher. */
      private USKStoreCheckCallbacks callbacks;

      /** Whether store checks should run with real-time bias. */
      private boolean realTimeFlag;

      /** Creates a new builder with unset fields. */
      Builder() {}

      /**
       * Sets the key watch set used to derive datastore checkers.
       *
       * @param watchingKeys watch set used to build store checkers; must be non-null
       * @return this builder for method chaining
       */
      Builder watchingKeys(USKKeyWatchSet watchingKeys) {
        this.watchingKeys = watchingKeys;
        return this;
      }

      /**
       * Sets the attempt manager used to schedule polling attempts.
       *
       * @param attempts attempt manager to be updated after store checks; must be non-null
       * @return this builder for method chaining
       */
      Builder attempts(USKAttemptManager attempts) {
        this.attempts = attempts;
        return this;
      }

      /**
       * Sets the parent requester used for scheduling decisions.
       *
       * @param parent requester used to schedule network activity; must be non-null
       * @return this builder for method chaining
       */
      Builder parent(ClientRequester parent) {
        this.parent = parent;
        return this;
      }

      /**
       * Sets whether the coordinator should only check the store.
       *
       * @param checkStoreOnly {@code true} to avoid network fetches and only check the store
       * @return this builder for method chaining
       */
      Builder checkStoreOnly(boolean checkStoreOnly) {
        this.checkStoreOnly = checkStoreOnly;
        return this;
      }

      /**
       * Sets the USK manager used to query the latest known slot.
       *
       * @param uskManager manager used to look up slot values; must be non-null
       * @return this builder for method chaining
       */
      Builder uskManager(USKManager uskManager) {
        this.uskManager = uskManager;
        return this;
      }

      /**
       * Sets the base USK being checked.
       *
       * @param origUSK base USK to check; must be non-null
       * @return this builder for method chaining
       */
      Builder origUSK(USK origUSK) {
        this.origUSK = origUSK;
        return this;
      }

      /**
       * Sets the callbacks used to notify the owning fetcher.
       *
       * @param callbacks callback interface for completion and scheduling events; must be non-null
       * @return this builder for method chaining
       */
      Builder callbacks(USKStoreCheckCallbacks callbacks) {
        this.callbacks = callbacks;
        return this;
      }

      /**
       * Sets whether scheduling should use real-time bias.
       *
       * @param realTimeFlag {@code true} to prefer real-time scheduling priorities
       * @return this builder for method chaining
       */
      Builder realTimeFlag(boolean realTimeFlag) {
        this.realTimeFlag = realTimeFlag;
        return this;
      }

      /**
       * Builds the {@link Params} instance from the configured fields.
       *
       * @return an immutable parameter bundle for the coordinator
       */
      Params build() {
        return new Params(this);
      }
    }
  }

  /**
   * Creates a coordinator using a parameter bundle.
   *
   * <p>The parameter bundle should contain fully initialized collaborators that remain valid for
   * the lifetime of the coordinator.
   *
   * @param params parameter bundle with collaborators and scheduling flags; must be non-null
   */
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
   * <p>The coordinator ensures only one store checker is active at a time. If a checker is already
   * running, the method returns {@code true} to indicate that no new registration was performed. If
   * there are no datastore checkers to run, it returns {@code false} to signal that no store check
   * is required.
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
      // USKStoreCheckerGetter itself will automatically call back to fillKeysWatching, so there is
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
   * @param toNetwork whether the scheduler intended a network sending for the checker
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
      // Note: optionally start USKAttempts only when a datastore check shows no progress.
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

  /**
   * Returns whether a store check is currently running.
   *
   * @return {@code true} if a store checker getter is active, otherwise {@code false}
   */
  boolean isStoreCheckRunning() {
    synchronized (this) {
      return runningStoreChecker != null;
    }
  }

  /**
   * Cancels any running store checker and unregisters it from the scheduler.
   *
   * <p>If no checker is running, the method is a no-op.
   *
   * @param context client context used to unregister the checker; must not be null
   */
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

  /**
   * Builds a store checker for the given edition.
   *
   * @param ed edition used to select datastore sub-checkers
   * @return a store checker instance, or {@code null} if no checks are required
   */
  private USKStoreChecker buildStoreChecker(long ed) {
    List<USKKeyWatchSet.KeyList.StoreSubChecker> checkers = watchingKeys.getDatastoreCheckers(ed);
    if (checkers == null) return null;
    return new USKStoreChecker(checkers);
  }

  /**
   * Bundles of datastore sub-checkers used to query the local store for candidate editions.
   *
   * <p>This helper merges keys from multiple sources and forwards completion notifications back to
   * the underlying sub-checkers.
   */
  final class USKStoreChecker {

    /** Sub-checkers contributing keys to a query in the datastore. */
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
     * Merges keys from all sub-checkers into a deduplicated array.
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

  /** Callbacks used by {@link USKStoreCheckCoordinator} to coordinate with the owning fetcher. */
  interface USKStoreCheckCallbacks {
    /**
     * Completes the fetcher successfully after store-only checking finishes.
     *
     * @param context client context used to complete and notify callbacks; must be non-null
     */
    void finishSuccess(ClientContext context);

    /**
     * Notifies subscribers that network activity is about to begin.
     *
     * @param context client context used to notify subscribers; must be non-null
     */
    void notifySendingToNetwork(ClientContext context);

    /**
     * Processes attempts after a store check completes.
     *
     * @param attempts polling attempts to start or update; may be empty but not null
     * @param context client context used for scheduling and callbacks; must be non-null
     */
    void processAttemptsAfterStoreCheck(USKAttempt[] attempts, ClientContext context);

    /**
     * Determines whether scheduling should be deferred until DBR hints finish.
     *
     * @return {@code true} to defer scheduling until DBR hint fetches are complete
     */
    boolean shouldDeferUntilDBRs();

    /**
     * Updates whether scheduling should wait for DBR hints to finish.
     *
     * @param value {@code true} to defer scheduling until DBR hint fetches complete
     */
    void setScheduleAfterDBRsDone(boolean value);

    /**
     * Indicates whether the owning fetcher has been canceled.
     *
     * @return {@code true} if the fetcher is canceled and should stop scheduling
     */
    boolean isCancelled();

    /**
     * Returns the fetch context used for store check operations.
     *
     * @return fetch context used by the owning fetcher
     */
    FetchContext fetcherContext();

    /**
     * Returns the owning fetcher instance.
     *
     * @return the fetcher that owns this coordinator
     */
    USKFetcher fetcher();
  }
}
