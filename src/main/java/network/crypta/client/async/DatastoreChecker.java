package network.crypta.client.async;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Objects;
import java.util.Random;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.Node;
import network.crypta.node.PrioRunnable;
import network.crypta.node.RequestStarter;
import network.crypta.node.SendableGet;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.io.NativeThread;
import network.crypta.support.math.MersenneTwister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Checks the node's local datastore for blocks associated with queued transient requests.
 *
 * <p>This component consumes lightweight queue entries that reference a set of keys and a
 * corresponding request object. For each key it verifies whether a matching {@code KeyBlock} is
 * already present locally. When a block is found, the request's scheduler is informed so the
 * request can continue without network traffic. When a block is not found, the request remains
 * eligible for normal routing. The checker runs on a dedicated executor thread and can be started
 * lazily, in which case the thread terminates once the queue becomes empty.
 *
 * <p>Typical usage is to call {@link #queueRequest(SendableGet, BlockSet)} from request setup logic
 * to enqueue keys for a quick local presence test before incurring network work. This class does
 * not mutate request state directly; it delegates to {@code ClientRequestScheduler} for finishing
 * registration and advancing request lifecycle. The checker is not intended for persistent store
 * sweeps or maintenance tasks.
 *
 * <ul>
 *   <li>Processes items by priority class; lower numeric values are visited first.
 *   <li>Uses bounded waits when the queue is empty and supports lazy shutdown.
 *   <li>Signals the scheduler on found blocks and on completion of registration.
 * </ul>
 *
 * <p>Thread-safety: enqueuing and internal state are synchronized. The class is safe to use from
 * multiple threads; public methods that alter state synchronize on {@code this}. Callers should
 * avoid holding locks when invoking callbacks into external components.
 *
 * @author Matthew Toseland &lt;toad@amphibian.dyndns.org&gt; (0xE43DA450)
 * @see SendableGet
 * @see network.crypta.client.async.ClientRequestScheduler
 */
public class DatastoreChecker implements PrioRunnable {
  private static final Logger LOG = LoggerFactory.getLogger(DatastoreChecker.class);

  /** True to start the DatastoreChecker thread lazily (mostly for simulations). */
  private final boolean lazy;

  /** True if lazy is true and the datastore checker thread is running */
  private boolean running;

  private final PriorityAwareExecutor executor;
  private final String threadName;

  // Setting these to 1, 3 kills 1/3rd of datastore checks.
  // 2, 5 gives 40% etc.
  // In normal operation KILL_BLOCKS should be 0 !!!!
  static int killBlocks = 0;
  static final int RESET_COUNTER = 100;

  // No static initialization required

  private static class QueueItem {
    /**
     * Request which we will call finishRegister() for when we have checked the keys lists.
     * Deactivated (if persistent).
     */
    final SendableGet getter;

    /** Arrays of keys to check. */
    Key[] keys;

    final BlockSet blockSet;

    QueueItem(Key[] keys, SendableGet getter, BlockSet blockSet) {
      this.getter = getter;
      this.keys = keys;
      this.blockSet = blockSet;
    }

    @Override
    public boolean equals(Object o) {
      // Hack to make queue.remove() work, see removeRequest() below.
      if (!(o instanceof QueueItem queueItem)) return false;
      return Objects.equals(getter, queueItem.getter);
    }

    @Override
    public int hashCode() {
      if (getter == null) {
        return 0;
      }
      return getter.hashCode();
    }
  }

  /** List of requests to check the datastore for, bucketed by priority. */
  private final ArrayList<ArrayDeque<QueueItem>> queue;

  private volatile ClientContext context;
  private final Node node;

  /**
   * Sets the client context used to get schedulers and to queue persistence-related jobs.
   *
   * <p>The context must be set before processing begins. This method is synchronized because the
   * checker may read the context from its worker thread while clients may update it during
   * initialization or testing.
   *
   * @param context client execution context; must not be {@code null}. The reference is stored and
   *     later accessed from the checker thread.
   */
  public synchronized void setContext(ClientContext context) {
    this.context = context;
  }

  /**
   * Creates a new datastore checker.
   *
   * <p>When {@code lazyStart} is {@code true}, the checker thread starts only when there are items
   * to process and stops automatically when the queue drains. Otherwise, the thread remains active
   * and waits for work. The executor is used to run the checker with the supplied thread name and a
   * normal priority.
   *
   * @param node the owning node used to fetch blocks from the local store as a last resort when a
   *     {@code BlockSet} is not provided; must not be {@code null}.
   * @param lazyStart whether the checker thread should be started on demand and terminate when idle
   *     (useful in simulations and tests).
   * @param executor executor that accepts the checker as a task and handles priority; must not be
   *     {@code null}.
   * @param threadName descriptive name used when submitting the checker to the executor; used for
   *     thread identification and diagnostics.
   */
  public DatastoreChecker(
      Node node, boolean lazyStart, PriorityAwareExecutor executor, String threadName) {
    this.node = node;
    this.lazy = lazyStart;
    this.executor = executor;
    this.threadName = threadName;
    int priorities = RequestStarter.NUMBER_OF_PRIORITY_CLASSES;
    queue = new ArrayList<>(priorities);
    for (int i = 0; i < priorities; i++) queue.add(new ArrayDeque<>());
  }

  /**
   * Enqueues a transient request whose keys should be probed in the local datastore.
   *
   * <p>This method collects keys from the provided {@link SendableGet} and inserts a work item into
   * the priority queue corresponding to the request's priority class. If {@code blocks} is not
   * {@code null}, it is consulted first to avoid a best-effort fetch from the node. The method
   * returns immediately and wakes the worker if necessary. Duplicate enqueues for the same request
   * within the same priority bucket are ignored with a debug log.
   *
   * @param getter request whose keys will be checked; must supply a non-empty key list. The
   *     instance is used for identification and later completion callbacks.
   * @param blocks optional snapshot of known blocks keyed by {@code Key}; when present it is used
   *     to resolve hits without consulting the node's store.
   */
  public void queueRequest(SendableGet getter, BlockSet blocks) {
    Key[] checkKeys = getter.listKeys();
    short prio = getter.getPriorityClass();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Queueing transient request {} priority {} keys {}", getter, prio, checkKeys.length);
    // Potential optimization: check using store.probablyInStore
    ArrayList<Key> finalKeysToCheck = new ArrayList<>(checkKeys.length);
    synchronized (this) {
      Collections.addAll(finalKeysToCheck, checkKeys);
      QueueItem queueItem = new QueueItem(finalKeysToCheck.toArray(new Key[0]), getter, blocks);
      if (LOG.isDebugEnabled() && queue.get(prio).contains(queueItem)) {
        LOG.error("Transient request {} is already queued!", getter);
        return;
      }
      queue.get(prio).add(queueItem);
      wakeUp();
    }
  }

  /**
   * Runs the checker event loop on the executor thread.
   *
   * <p>The loop processes a single queue item at a time and blocks with a bounded wait when the
   * queue is empty. In lazy mode, the method returns once the queue has drained so the caller can
   * release the thread. Any unexpected exceptions are logged, and the loop continues to reduce the
   * chance of losing queued work.
   */
  @Override
  public void run() {
    while (true) {
      try {
        if (realRun()) return; // Lazy termination.
      } catch (Exception e) {
        LOG.error("Caught {} in datastore checker thread", e, e);
      }
    }
  }

  /**
   * Process a single job, waiting if necessary.
   *
   * @return True if lazy=true, and there are no jobs to run.
   */
  private boolean realRun() {
    Random random = (killBlocks != 0) ? new MersenneTwister() : null;

    QueueItem item = waitForQueueItemOrTerminate();
    if (item == null) {
      return true; // Lazy termination
    }

    Key[] keys = item.keys;
    SendableGet getter = item.getter;
    BlockSet blocks = item.blockSet;

    ClientRequestScheduler sched;
    synchronized (this) {
      sched = getter.getScheduler(context);
    }
    boolean anyValid = processKeys(keys, blocks, random, sched);

    if (LOG.isDebugEnabled()) LOG.debug("Checked {} keys", keys.length);

    if (getter.persistent()) {
      queueFinishRegisterPersistent(getter, sched, anyValid);
    } else {
      sched.finishRegister(new SendableGet[] {getter}, false, anyValid);
    }
    return false;
  }

  @SuppressWarnings("java:S2142")
  private synchronized QueueItem waitForQueueItemOrTerminate() {
    while (true) {
      for (short prio = 0; prio < queue.size(); prio++) {
        QueueItem trans = queue.get(prio).pollFirst();
        if (trans != null) {
          debugCheckingTransientRequest(trans.getter, prio, queue.get(prio).size());
          return trans;
        }
      }
      debugWaitingForTransientRequests();
      if (lazy) {
        running = false;
        return null;
      }
      try {
        wait(SECONDS.toMillis(100));
      } catch (InterruptedException _) {
        // Swallow and continue waiting; do not re-interrupt to avoid the hot loop
      }
    }
  }

  private static void debugCheckingTransientRequest(
      SendableGet getter, short prio, int remainingInPrio) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Checking transient request {} prio {} of {}", getter, prio, remainingInPrio);
    }
  }

  private static void debugWaitingForTransientRequests() {
    if (LOG.isDebugEnabled()) LOG.debug("Waiting for more transient requests");
  }

  private boolean processKeys(
      Key[] keys, BlockSet blocks, Random random, ClientRequestScheduler sched) {
    boolean anyValid = false;
    for (Key key : keys) {
      if (random != null && random.nextInt(RESET_COUNTER) < killBlocks) {
        anyValid = true;
        continue;
      }
      KeyBlock block =
          (blocks != null)
              ? blocks.get(key)
              : node.storage().fetch(key, true, true, false, false, null);
      if (block != null) {
        if (LOG.isDebugEnabled()) LOG.debug("Found key");
        sched.tripPendingKey(block);
      } else {
        anyValid = true;
      }
    }
    return anyValid;
  }

  private void queueFinishRegisterPersistent(
      final SendableGet getter, final ClientRequestScheduler sched, final boolean anyValid) {
    try {
      context.jobRunner.queue(
          new PersistentJob() {
            @Override
            public boolean run(ClientContext context) {
              try {
                sched.finishRegister(new SendableGet[] {getter}, true, anyValid);
              } catch (Exception e) {
                LOG.error("Failed to register {}: {}", getter, e, e);
                try {
                  getter.onFailure(
                      new LowLevelGetException(
                          LowLevelGetException.INTERNAL_ERROR, "Internal error: " + e, e),
                      null,
                      context);
                } catch (Exception _) {
                  LOG.error("Failed to fail: {}", e, e);
                }
              }
              return false;
            }

            @Override
            public String toString() {
              return "DatastoreCheckerFinishRegister";
            }
          },
          NativeThread.PriorityLevel.NORM_PRIORITY.value);
    } catch (PersistenceDisabledException e) {
      LOG.warn("Persistence unexpectedly disabled while queuing finishRegister job", e);
    }
  }

  synchronized void wakeUp() {
    if (lazy && !running) {
      start();
      return;
    }
    notifyAll();
  }

  /**
   * Starts the checker thread if needed.
   *
   * <p>In lazy mode this method is a no-op when the queue is empty or already running. Otherwise,
   * it submits the checker to the configured {@link PriorityAwareExecutor} using the provided
   * thread name and a normal priority. This method is synchronized to coordinate with enqueuing and
   * waiting logic.
   */
  public synchronized void start() {
    if (lazy) {
      if (isEmpty()) return;
      if (running) return;
    }
    running = true;
    executor.execute(this, threadName);
  }

  private synchronized boolean isEmpty() {
    for (ArrayDeque<QueueItem> q : queue) {
      if (!q.isEmpty()) return false;
    }
    return true;
  }

  /**
   * Returns the scheduling priority for the checker thread.
   *
   * <p>The value is passed to the {@link PriorityAwareExecutor} when the checker is scheduled and
   * maps to {@link NativeThread.PriorityLevel#NORM_PRIORITY}. It does not reflect request
   * priorities inside the internal queue.
   *
   * @return a fixed integer corresponding to normal priority for the worker thread.
   */
  @Override
  public int getPriority() {
    return NativeThread.PriorityLevel.NORM_PRIORITY.value;
  }

  /**
   * Removes a previously queued transient request, if present.
   *
   * <p>The removal is best-effort and only affects the current in-memory queue; it does not cancel
   * already-running work. The method compares requests by identity to locate the matching queue
   * entry in the bucket associated with {@code prio}.
   *
   * @param request the request to remove; compared by object identity against queued items.
   * @param persistent whether the original request was persistent; the checker only maintains a
   *     transient queue and ignores this flag other than for logging.
   * @param context client context supplied for symmetry with other APIs; not used to perform the
   *     removal.
   * @param prio the priority bucket from which the request should be removed; must be within the
   *     range defined by {@link RequestStarter#NUMBER_OF_PRIORITY_CLASSES}.
   */
  public void removeRequest(
      SendableGet request, boolean persistent, ClientContext context, short prio) {
    if (LOG.isDebugEnabled())
      LOG.debug("Removing request prio={} persistent={} ctx={}", prio, persistent, context);
    QueueItem requestMatcher = new QueueItem(null, request, null);
    synchronized (this) {
      if (!queue.get(prio).remove(requestMatcher)) return;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Removed transient request");
  }
}
