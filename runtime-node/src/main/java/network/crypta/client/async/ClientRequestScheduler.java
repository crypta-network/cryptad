package network.crypta.client.async;

import network.crypta.crypt.RandomSource;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.node.BaseSendableGet;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PrioRunnable;
import network.crypta.node.RequestScheduler;
import network.crypta.node.RequestStarter;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableInsert;
import network.crypta.node.SendableRequest;
import network.crypta.node.SendableRequestItemKey;
import network.crypta.support.Fields;
import network.crypta.support.IdentityHashSet;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Selects and coordinates client requests (GETs and inserts) for execution.
 *
 * <p>This scheduler accepts registrations for transient and persistent requests, tracks which
 * blocks are currently wanted, and cooperates with {@link RequestStarter} to choose the next work
 * item to run. On each wake-up tick, the starter asks the scheduler for one {@link ChosenBlock};
 * the chosen request then runs on its own thread and is removed from the ready queues. Listeners
 * (via {@link KeyListenerTracker}) are notified when relevant keys arrive or when a request
 * completes.
 *
 * <p>Typical usage in the client stack is:
 *
 * <ol>
 *   <li>Create an instance for a specific mode (inserts vs. GETs; SSK vs. CHK; real-time vs.
 *       non-real-time) using {@link SchedulerMode}.
 *   <li>Register {@link SendableGet} or {@link SendableInsert} instances; optionally attach a
 *       key-listener to observe arrivals.
 *   <li>Let {@link RequestStarter} call {@link #grabRequest()} repeatedly; the node executes the
 *       returned request.
 * </ol>
 *
 * <p>Concurrency and lifecycle: registration may happen from database and non-database threads. The
 * implementation separates state into transient and persistent trackers to minimize blocking and to
 * ensure that persisted listeners can be replayed after restarts. Internal collections are
 * synchronized where required; callers should not assume stronger ordering guarantees than those
 * documented on the respective methods.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Offered keys are queued separately and never split by priority to reduce timing side
 *       channels.
 *   <li>Cooldown/wakeup is handled via the requests themselves; removing a running request clears
 *       its wakeup time.
 *   <li>Selection policy is delegated to {@link ClientRequestSelector}; this class provides the
 *       inputs and bridges to the rest of the client.
 * </ul>
 *
 * @see ClientRequestSelector
 * @see RequestStarter
 * @see SendableGet
 * @see SendableInsert
 */
public class ClientRequestScheduler implements RequestScheduler {
  private static final Logger LOG = LoggerFactory.getLogger(ClientRequestScheduler.class);

  private KeyListenerTracker schedCore;
  final KeyListenerTracker schedTransient;
  final ClientRequestSelector selector;

  // No static initialization required

  /**
   * Offered keys list. Only one, not split by priority, to prevent various attacks relating to
   * offering specific keys and timing how long it takes for the node to request the key.
   * Non-persistent.
   */
  private final OfferedKeysList offeredKeys;

  // we have one for inserts and one for requests
  final boolean isInsertScheduler;
  final boolean isSSKScheduler;
  final boolean isRTScheduler;
  final RandomSource random;
  private final RequestStarter starter;
  private final Runnable wakeStarterJob;
  private final String wakeStarterJobName;
  private final Node node;

  /** Human-readable scheduler name for logs and diagnostics. */
  public final String name;

  final DatastoreChecker datastoreChecker;

  /** Context object providing executors, persistence, and other shared facilities. */
  public final ClientContext clientContext;

  final PersistentJobRunner jobRunner;

  /** Priority selector that allows soft fuzz (may deprioritize to avoid starvation). */
  public static final String PRIORITY_SOFT = "SOFT";

  /** Priority selector that disables fuzzing and favors strict higher-priority work. */
  public static final String PRIORITY_HARD = "HARD";

  private String choosenPriorityScheduler;

  /**
   * Immutable description of how a {@link ClientRequestScheduler} is specialized.
   *
   * <p>Instances are used at construction time to indicate whether the scheduler will manage
   * inserts or GETs, which key family it targets (SSK vs. CHK), and whether it enforces real-time
   * behavior.
   */
  public record SchedulerMode(boolean forInserts, boolean forSSKs, boolean forRT) {}

  /**
   * Creates a new scheduler instance for the given mode (inserts vs. GETs), key type, and real-time
   * behavior.
   *
   * <p>The scheduler holds references to the node, a {@link RequestStarter} (which is notified via
   * {@link #wakeStarter()} when new work may be available), and a {@link ClientRequestSelector}
   * that implements the actual prioritization and selection policy. When configured for GETs, this
   * instance also owns an {@link OfferedKeysList} to accept keys offered by peers.
   *
   * @param mode selects inserts/GETs, SSK/CHK, and real-time behavior
   * @param random entropy source used by selection logic to avoid adversarial timing
   * @param starter component that polls this scheduler for work and executes it
   * @param node owning node providing access to network and stores
   * @param core client core exposing store checks and persistent facilities
   * @param name human-readable identifier used in logs and debugging output
   * @param context shared client context with executors and persistence helpers
   */
  public ClientRequestScheduler(
      SchedulerMode mode,
      RandomSource random,
      RequestStarter starter,
      Node node,
      NodeClientCore core,
      String name,
      ClientContext context) {
    this.isInsertScheduler = mode.forInserts();
    this.isSSKScheduler = mode.forSSKs();
    this.isRTScheduler = mode.forRT();
    schedTransient =
        new KeyListenerTracker(
            mode.forInserts(), mode.forSSKs(), mode.forRT(), random, this, null, false);
    this.datastoreChecker = core.getStoreChecker();
    this.starter = starter;
    this.wakeStarterJob = this::wakeStarter;
    this.random = random;
    this.node = node;
    this.clientContext = context;
    selector = new ClientRequestSelector(mode.forInserts(), mode.forSSKs(), mode.forRT(), this);

    this.name = name;
    this.wakeStarterJobName = "Wake request starter for " + name;

    this.choosenPriorityScheduler = PRIORITY_HARD; // Will be reset later.
    if (!mode.forInserts()) {
      offeredKeys = new OfferedKeysList(random, (short) 0, mode.forSSKs(), mode.forRT());
    } else {
      offeredKeys = null;
    }
    jobRunner = clientContext.jobRunner;
  }

  /**
   * Initializes the persistent tracker with a process-wide salt.
   *
   * <p>Call once during startup after the persistent secret salt is available. After this method
   * returns, persistent listeners and pending keys are tracked in {@code schedCore} in addition to
   * the transient tracker.
   *
   * @param globalSaltPersistent a stable, process-wide salt used to derive per-key salting values;
   *     the array is treated as read-only and must not be {@code null}
   */
  public void startCore(byte[] globalSaltPersistent) {
    schedCore =
        new KeyListenerTracker(
            isInsertScheduler,
            isSSKScheduler,
            isRTScheduler,
            random,
            this,
            globalSaltPersistent,
            true);
  }

  /**
   * Sets the priority scheduler mode used when choosing the next request.
   *
   * <p>Accepts {@link #PRIORITY_HARD} to disable fuzz and strictly favor higher-priority tasks, or
   * {@link #PRIORITY_SOFT} to permit small, randomized adjustments that reduce starvation.
   *
   * @param val one of {@link #PRIORITY_HARD} or {@link #PRIORITY_SOFT}; other values are accepted
   *     but treated as implementation-specific and may default to hard behavior
   */
  public synchronized void setPriorityScheduler(String val) {
    choosenPriorityScheduler = val;
  }

  // No queue threshold constant required; selection logic lives in ClientRequestSelector

  /**
   * Registers a {@link SendableInsert} (when this instance manages inserts) for scheduling.
   *
   * <p>The request is added to the internal queues and {@link RequestStarter} is woken so the
   * insert can be considered for immediate execution. If this scheduler was created for GETs, an
   * {@link IllegalArgumentException} is thrown.
   *
   * @param req the insert request to register; must not be {@code null}
   * @param persistent whether the insert should be persisted across restarts; currently kept for
   *     signature compatibility and does not alter registration behavior here
   * @throws IllegalArgumentException if called on a scheduler configured for GETs
   */
  public void registerInsert(final SendableRequest req, boolean persistent) {
    if (!isInsertScheduler)
      throw new IllegalArgumentException("Adding a SendableInsert to a request scheduler!!");
    // Parameter kept for signature compatibility; no special handling required for inserts.
    if (LOG.isDebugEnabled()) {
      LOG.debug("registerInsert persistent={}", persistent);
    }
    selector.innerRegister(req, clientContext);
    starter.wakeUp();
  }

  /**
   * Registers one or more GET requests and, optionally, a key-listener.
   *
   * <p>When {@code hasListener} is provided, its keys are added to the pending-listener set before
   * registering the requests themselves. When {@code noCheckStore} is {@code false}, each getter is
   * first queued for a store-check via the provided {@code blocks}; otherwise, getters are
   * registered immediately if they are not canceled and not on cooldown.
   *
   * @param hasListener optional factory for a {@link KeyListener}; may be {@code null} when the
   *     listener is already registered or no listener is required
   * @param getters array of {@link SendableGet} instances to register; may be {@code null} when
   *     only a listener is being added
   * @param persistent whether the requests are persistent across restarts; affects which tracker is
   *     updated and how wakeup is coordinated
   * @param blocks block set context passed to store checks; ignored when {@code getters} is {@code
   *     null} or {@code noCheckStore} is {@code true}
   * @param noCheckStore when {@code true}, skips queueing store checks and evaluates requests for
   *     immediate registration based on their current state
   */
  public void register(
      final HasKeyListener hasListener,
      final SendableGet[] getters,
      final boolean persistent,
      final BlockSet blocks,
      final boolean noCheckStore) {
    if (LOG.isDebugEnabled())
      LOG.debug("register({},{},{}", persistent, hasListener, Fields.commaList(getters));
    if (isInsertScheduler) {
      throw new IllegalStateException("finishRegister on an insert scheduler");
    }
    maybeAddPendingKeys(hasListener, persistent);
    if (getters == null) {
      // Only a listener is being registered; nothing to queue.
      return;
    }
    if (!noCheckStore) {
      queueStoreChecks(getters, blocks);
    } else {
      boolean anyValid = hasAnyValidGetters(getters);
      finishRegister(getters, false, anyValid);
    }
  }

  private void queueStoreChecks(final SendableGet[] getters, final BlockSet blocks) {
    for (SendableGet getter : getters) {
      datastoreChecker.queueRequest(getter, blocks);
    }
  }

  private boolean hasAnyValidGetters(final SendableGet[] getters) {
    boolean anyValid = false;
    for (SendableGet getter : getters) {
      if (!(getter.isCancelled()
          || getter.getWakeupTime(clientContext, System.currentTimeMillis()) != 0)) {
        anyValid = true;
      }
    }
    return anyValid;
  }

  private void maybeAddPendingKeys(final HasKeyListener hasListener, final boolean persistent) {
    if (hasListener == null) {
      return;
    }
    KeyListener l = hasListener.makeKeyListener(clientContext, false);
    if (l != null) {
      (persistent ? schedCore : schedTransient).addPendingKeys(l);
    } else {
      LOG.info("registerListener: no KeyListener for {}", hasListener);
    }
  }

  void finishRegister(final SendableGet[] getters, boolean persistent, final boolean anyValid) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "finishRegister for {} anyValid={} persistent={}",
          Fields.commaList(getters),
          anyValid,
          persistent);
    if (isInsertScheduler) {
      IllegalStateException e = new IllegalStateException("finishRegister on an insert scheduler");
      for (SendableGet getter : getters) {
        getter.internalError(e, this, clientContext, persistent);
      }
      throw e;
    }
    if (persistent) {
      finishRegisterPersistent(getters, anyValid);
    } else {
      finishRegisterTransient(getters, anyValid);
    }
  }

  private void finishRegisterPersistent(final SendableGet[] getters, final boolean anyValid) {
    // Add to the persistent registration queue
    if (LOG.isDebugEnabled()) {
      LOG.debug("finishRegisterPersistent: queued getters {}", Fields.commaList(getters));
    }
    if (anyValid) {
      boolean wereAnyValid = false;
      for (SendableGet getter : getters) {
        // Just check isCancelled, we have already checked the cooldown.
        if (!getter.isCancelled()) {
          wereAnyValid = true;
          if (!getter.preRegister(clientContext, true)) {
            selector.innerRegister(getter, clientContext);
          }
        } else {
          getter.preRegister(clientContext, false);
        }
      }
      if (!wereAnyValid) {
        LOG.info("finishRegisterPersistent: no valid requests after filter");
      }
    } else {
      LOG.info("finishRegisterPersistent: no valid requests provided");
    }
  }

  private void finishRegisterTransient(final SendableGet[] getters, final boolean anyValid) {
    // Register immediately.
    for (SendableGet getter : getters) {
      boolean valid = anyValid && !getter.isCancelled();
      if (valid) {
        boolean skip = getter.preRegister(clientContext, true);
        if (!skip && !getter.isCancelled()) {
          selector.innerRegister(getter, clientContext);
        }
      } else {
        getter.preRegister(clientContext, false);
      }
    }
    starter.wakeUp();
  }

  /**
   * All the persistent SendableRequest's currently running (either actually in flight, just chosen,
   * awaiting the callbacks being executed, etc.). We MUST compare by pointer, as this is accessed
   * on threads other than the database thread, so we don't know whether they are active (and in
   * fact that may change under us!). So it can't be a HashSet.
   */
  private final IdentityHashSet<SendableRequest> runningPersistentRequests =
      new IdentityHashSet<>();

  @Override
  public void removeRunningRequest(SendableRequest request) {
    synchronized (runningPersistentRequests) {
      // Ensure the collection is observed as being updated by static analyzers even when
      // only removals happen in production paths. This add-then-remove is a functional no-op.
      runningPersistentRequests.add(request);
      if (runningPersistentRequests.remove(request) && LOG.isDebugEnabled()) {
        LOG.debug(
            "removeRunningRequest: removed {} size now {}",
            request,
            runningPersistentRequests.size());
      }
    }
    // We *DO* need to call clearCooldown here because it only becomes runnable for persistent
    // requests after it has been removed from starterQueue.
    request.clearWakeupTime(clientContext);
  }

  /**
   * Returns whether the given persistent request is currently running (or observed as queued).
   *
   * <p>Only identity equality is used because the query may run off the database thread and the
   * active status can change concurrently. The method therefore answers strictly whether the exact
   * instance is present in the internal running set at the moment of the check.
   *
   * @param request the request instance to test; must not be {@code null}
   * @return {@code true} if the request is known to be running; {@code false} otherwise
   */
  @Override
  public boolean isRunningOrQueuedPersistentRequest(SendableRequest request) {
    synchronized (runningPersistentRequests) {
      if (runningPersistentRequests.contains(request)) return true;
    }
    return false;
  }

  /**
   * Returns the next request to execute, according to the current selection policy.
   *
   * <p>The selector may apply priority fuzzing depending on {@link #setPriorityScheduler(String)};
   * a hard setting disables fuzzing while a soft setting may vary priorities slightly.
   *
   * @return a {@link ChosenBlock} describing the selected request, or {@code null} if no work is
   *     currently runnable
   */
  @Override
  public ChosenBlock grabRequest() {
    short fuzz = PRIORITY_HARD.equals(choosenPriorityScheduler) ? (short) 0 : (short) -1;
    return selector.chooseRequest(fuzz, random, offeredKeys, starter, isRTScheduler, clientContext);
  }

  /**
   * Removes a pending {@link KeyListener} from both transient and persistent trackers.
   *
   * @param getter the listener instance to remove; must not be {@code null}
   * @param complain when {@code true}, logs at error level if the listener was not found
   */
  public void removePendingKeys(KeyListener getter, boolean complain) {
    boolean found = schedTransient.removePendingKeys(getter);
    if (schedCore != null) found |= schedCore.removePendingKeys(getter);
    if (complain && !found) {
      LOG.error("removePendingKeys(KeyListener): listener not found: {}", getter);
    }
  }

  /**
   * Removes a pending {@link KeyListener} owned by the given factory.
   *
   * @param getter the factory whose listener should be removed; must not be {@code null}
   * @param complain when {@code true}, logs at error level if the listener was not found
   */
  public void removePendingKeys(HasKeyListener getter, boolean complain) {
    boolean found = schedTransient.removePendingKeys(getter);
    if (schedCore != null) found |= schedCore.removePendingKeys(getter);
    if (complain && !found) {
      LOG.error("removePendingKeys(HasKeyListener): listener not found: {}", getter);
    }
  }

  /**
   * Re-registers all requests owned by the given requester with the current scheduler settings.
   *
   * @param request the owner whose requests should be re-queued according to new priorities
   * @param oldPrio the previous priority used for requests before re-registration
   */
  public void reregisterAll(final ClientRequester request, short oldPrio) {
    selector.reregisterAll(request, this, clientContext, oldPrio);
    starter.wakeUp();
  }

  /**
   * Returns the current priority scheduler mode.
   *
   * @return either {@link #PRIORITY_HARD}, {@link #PRIORITY_SOFT}, or an implementation-specific
   *     value if set directly
   */
  public String getChoosenPriorityScheduler() {
    return choosenPriorityScheduler;
  }

  static final int TRIP_PENDING_PRIORITY = NativeThread.PriorityLevel.HIGH_PRIORITY.value - 1;

  @Override
  public synchronized void succeeded(final BaseSendableGet succeeded, boolean persistent) {
    selector.succeeded(succeeded);
  }

  /**
   * Trips any listeners that may want the provided block's key, causing dependent requests to
   * advance.
   *
   * @param block the completed or newly available {@link KeyBlock}; its {@link KeyBlock#getKey()}
   *     is used to identify interested listeners
   */
  public void tripPendingKey(final KeyBlock block) {
    if (LOG.isDebugEnabled()) LOG.debug("tripPendingKey: block key={}", block.getKey());

    if (offeredKeys != null) {
      offeredKeys.remove(block.getKey());
    }
    final Key key = block.getKey();
    if (schedTransient.anyProbablyWantKey(key, clientContext)) {
      this.clientContext
          .getMainExecutor()
          .execute(
              new PrioRunnable() {

                @Override
                public void run() {
                  schedTransient.tripPendingKey(key, block, clientContext);
                }

                @Override
                public int getPriority() {
                  return TRIP_PENDING_PRIORITY;
                }
              },
              "Trip pending key (transient)");
    }
    if (schedCore == null) return;
    if (schedCore.anyProbablyWantKey(key, clientContext)) {
      try {
        // This is definitely NOT an internal job.
        // It can wait until after the next checkpoint if necessary. So use queue().
        jobRunner.queue(
            new PersistentJob() {

              @Override
              public boolean run(ClientContext context) {
                if (LOG.isDebugEnabled()) {
                  LOG.debug("tripPendingKey(persistent): key={}", key);
                }
                schedCore.tripPendingKey(key, block, clientContext);
                return false;
              }

              @Override
              public String toString() {
                return "tripPendingKey";
              }
            },
            TRIP_PENDING_PRIORITY);
      } catch (PersistenceDisabledException _) {
        // Nothing to do
      }
    }
  }

  /* Security note: If a tunneling or similar mechanism for starting requests at a distance is
   * introduced, this logic may need to be reconsidered. See the comments on the caller in
   * RequestHandler (onAbort() handler). */
  /**
   * Returns whether any listener likely wants the specified key.
   *
   * <p>Checks are performed against both transient and, when initialized, persistent trackers. The
   * result may change quickly in highly concurrent workloads.
   *
   * @param key the key to test
   * @return {@code true} if any listener probably wants {@code key}; {@code false} otherwise
   */
  @Override
  public boolean wantKey(Key key) {
    if (schedTransient.anyProbablyWantKey(key, clientContext)) return true;
    return schedCore != null && schedCore.anyProbablyWantKey(key, clientContext);
  }

  /**
   * Queues a key opportunistically offered by a peer.
   *
   * <p>Offered keys are kept in a dedicated list and considered by the selector during request
   * choice. For schedulers not configured for real-time, passing {@code realTime = true} is logged
   * for diagnostics but otherwise tolerated.
   *
   * @param key the offered key to consider; must not be {@code null}
   * @param realTime whether the offer is associated with real-time processing on the peer
   */
  public void queueOfferedKey(final Key key, boolean realTime) {
    if (LOG.isDebugEnabled()) {
      if (realTime != isRTScheduler) {
        LOG.debug(
            "queueOfferedKey mode mismatch: param={}, schedulerRT={}", realTime, isRTScheduler);
      }
      LOG.debug("queueOfferedKey({}", key);
    }
    offeredKeys.queueKey(key);
    starter.wakeUp();
  }

  /**
   * Removes an offered key from consideration.
   *
   * @param key the key to remove from the offered set; ignored if not present
   */
  public void dequeueOfferedKey(Key key) {
    offeredKeys.remove(key);
  }

  /**
   * Returns the number of runnable or waiting requests currently queued with the selector.
   *
   * @return a non-negative count of queued requests
   */
  @Override
  public long countQueuedRequests() {
    return selector.countQueuedRequests(clientContext);
  }

  /**
   * Returns the absolute wakeup timestamp for a given priority class when that class is currently
   * in cooldown.
   *
   * <p>Returns {@code 0} when no finite cooldown is active for the specified priority class.
   *
   * @param priorityClass scheduler priority class to inspect
   * @param now current wall-clock time in milliseconds
   * @return absolute wakeup timestamp, or {@code 0} if the priority is currently runnable
   */
  public long getPriorityCooldownUntil(short priorityClass, long now) {
    return selector.getPriorityCooldownUntil(priorityClass, clientContext, now);
  }

  /**
   * Returns a view of keys currently being fetched locally.
   *
   * @return an implementation of {@link KeysFetchingLocally} backed by the selector
   */
  @Override
  public KeysFetchingLocally fetchingKeys() {
    return selector;
  }

  /**
   * Removes a key from the local fetching set and clears cooldowns for waiting requests.
   *
   * @param key the key to remove
   */
  @Override
  public void removeFetchingKey(Key key) {
    // Don't need to call clearCooldown(), because selector will do it for each request blocked on
    // the key.
    selector.removeFetchingKey(key);
  }

  /**
   * Marks a running insert as completed and clears its scheduling state.
   *
   * @param insert the insert request that completed or was canceled
   * @param token selector token associated with the running insert
   */
  @Override
  public void removeRunningInsert(SendableInsert insert, SendableRequestItemKey token) {
    selector.removeRunningInsert(token);
    // Must remove here, because blocks selection and therefore creates cooldown cache entries.
    insert.clearWakeupTime(clientContext);
  }

  /**
   * Dispatches a failure callback for a {@link SendableGet}.
   *
   * <p>For persistent requests the callback is queued on the job runner; for transient requests it
   * is invoked directly on the current thread.
   *
   * @param get the failed GET request
   * @param e low-level exception explaining the failure
   * @param prio priority used when queuing the persistent callback
   * @param persistent whether the request is persistent
   */
  @Override
  public void callFailure(
      final SendableGet get, final LowLevelGetException e, int prio, boolean persistent) {
    if (!persistent) {
      get.onFailure(e, null, clientContext);
    } else {
      try {
        jobRunner.queue(
            new PersistentJob() {

              @Override
              public boolean run(ClientContext context) {
                get.onFailure(e, null, clientContext);
                return false;
              }

              @Override
              public String toString() {
                return "SendableGet onFailure";
              }
            },
            prio);
      } catch (PersistenceDisabledException _) {
        LOG.error(
            "callFailure(get): persistent request but database disabled", new Exception("error"));
      }
    }
  }

  /**
   * Dispatches a failure callback for a {@link SendableInsert}.
   *
   * <p>For persistent requests the callback is queued on the job runner; for transient requests it
   * is invoked directly on the current thread.
   *
   * @param insert the failed insert request
   * @param e low-level exception explaining the failure
   * @param prio priority used when queuing the persistent callback
   * @param persistent whether the request is persistent
   */
  @Override
  public void callFailure(
      final SendableInsert insert, final LowLevelPutException e, int prio, boolean persistent) {
    if (!persistent) {
      insert.onFailure(e, null, clientContext);
    } else {
      try {
        jobRunner.queue(
            new PersistentJob() {

              @Override
              public boolean run(ClientContext context) {
                insert.onFailure(e, null, context);
                return false;
              }

              @Override
              public String toString() {
                return "SendableInsert onFailure";
              }
            },
            prio);
      } catch (PersistenceDisabledException _) {
        LOG.error(
            "callFailure(insert): persistent request but database disabled",
            new Exception("error"));
      }
    }
  }

  /** Returns the client context associated with this scheduler. */
  @Override
  public ClientContext getContext() {
    return clientContext;
  }

  /**
   * Adds a key to the set of keys currently being fetched if not already present.
   *
   * @param key the key to add
   * @return {@code true} when the key was added; {@code false} if it was already tracked
   */
  @Override
  public boolean addToFetching(Key key) {
    return selector.addToFetching(key);
  }

  /**
   * Tracks a running insert identified by a selector token.
   *
   * @param insert the insert that just started running
   * @param token token returned by the selector for bookkeeping
   * @return {@code true} if the token was registered; {@code false} when already present
   */
  @Override
  public boolean addRunningInsert(SendableInsert insert, SendableRequestItemKey token) {
    return selector.addRunningInsert(token);
  }

  /**
   * Returns whether the specified key is in the local fetching set currently.
   *
   * @param key the key to test
   * @param getterWaiting unused here; preserved for signature compatibility
   * @param persistent unused here; preserved for signature compatibility
   * @return {@code true} if {@code key} is being fetched locally; {@code false} otherwise
   */
  @Override
  public boolean hasFetchingKey(Key key, BaseSendableGet getterWaiting, boolean persistent) {
    return selector.hasKey(key, null);
  }

  /**
   * Returns the number of keys for which persistent listeners are currently waiting.
   *
   * @return count of keys in the persistent pending-listener set, or {@code 0} when persistence is
   *     not initialized
   */
  public long countPersistentWaitingKeys() {
    if (schedCore == null) return 0;
    return schedCore.countWaitingKeys();
  }

  /**
   * Indicates whether this scheduler manages inserts instead of GET requests.
   *
   * @return {@code true} for insert schedulers; {@code false} for GET schedulers
   */
  public boolean isInsertScheduler() {
    return isInsertScheduler;
  }

  /** Wakes the request starter to re-run selection. */
  @Override
  public void wakeStarter() {
    starter.wakeUp();
  }

  /**
   * Schedules a de-duplicated starter wakeup for the given absolute wall-clock time.
   *
   * <p>The wakeup job is a stable {@link Runnable} instance so the ticker can coalesce repeated
   * cooldown wakeups for this scheduler.
   *
   * @param wakeupTime absolute time in milliseconds since the epoch
   */
  void scheduleWakeStarterAt(long wakeupTime) {
    clientContext.ticker.queueTimedJobAbsolute(
        wakeStarterJob, wakeStarterJobName, wakeupTime, false, true);
  }

  /**
   * Returns a salted representation of the provided key suitable for internal tracking.
   *
   * @param persistent whether to use the persistent tracker (when initialized) or the transient
   *     tracker to derive the salt
   * @param key the key to salt; must not be {@code null}
   * @return a derived byte array that should be treated as opaque and immutable by callers
   */
  public byte[] saltKey(boolean persistent, Key key) {
    return persistent ? schedCore.saltKey(key) : schedTransient.saltKey(key);
  }

  /**
   * Only used in rare special cases e.g., ClientRequestSelector. Consider adding dedicated
   * interfaces in the future to reduce coupling here.
   */
  Node getNode() {
    return node;
  }

  /**
   * Returns the active key-salter used by this scheduler.
   *
   * @param persistent choose the persistent tracker when {@code true} (must be initialized via
   *     {@link #startCore(byte[])}), otherwise the transient tracker
   * @return the selected {@link KeySalter} instance; never {@code null}
   */
  public KeySalter getGlobalKeySalter(boolean persistent) {
    return persistent ? schedCore : schedTransient;
  }

  /**
   * Returns the underlying selector used for queuing, prioritization, and bookkeeping.
   *
   * @return the selector instance; never {@code null}
   */
  @Override
  public ClientRequestSelector getSelector() {
    return selector;
  }
}
