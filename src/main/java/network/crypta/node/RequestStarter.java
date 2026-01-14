package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;

import network.crypta.client.async.ChosenBlock;
import network.crypta.client.async.ChosenBlockImpl;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.Key;
import network.crypta.node.NodeStats.RejectReason;
import network.crypta.support.RandomGrabArrayItem;
import network.crypta.support.RandomGrabArrayItemExclusionList;
import network.crypta.support.math.RunningAverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates dequeuing and starting of client requests.
 *
 * <p>This component is the only path for starting requests; callers do not start requests directly.
 * It cooperates with a {@link RequestScheduler} to grab work and with the node executor to launch
 * per-request sender threads. Starters operate in two modes (bulk or real‑time) and for different
 * request types (CHK/SSK, fetch/insert); the {@link #name} reflects the mode for diagnostics.
 *
 * <p>Threading and interrupts: the {@link #run()} loop waits for work and throttles between
 * requests. It honors interrupts in blocking waits and exits cleanly so the executor can stop the
 * thread. Short opennet bootstrap deferrals use a one‑second wait that is also interruptible and
 * responsive to {@link #wakeUp()} notifications.
 *
 * <p>Throttling: the per‑request delay is obtained from {@link BaseRequestThrottle}. Transient
 * interrupts during throttling are swallowed so later iterations can resume delaying.
 */
public class RequestStarter implements Runnable, RandomGrabArrayItemExclusionList {
  private static final Logger LOG = LoggerFactory.getLogger(RequestStarter.class);

  /*
   * Priority classes
   */
  /** Anything more important than FProxy */
  public static final short MAXIMUM_PRIORITY_CLASS = 0;

  /** FProxy etc */
  public static final short INTERACTIVE_PRIORITY_CLASS = 1;

  /** FProxy splitfile fetches */
  public static final short IMMEDIATE_SPLITFILE_PRIORITY_CLASS = 2;

  /** USK updates etc */
  public static final short UPDATE_PRIORITY_CLASS = 3;

  /** Bulk splitfile fetches */
  public static final short BULK_SPLITFILE_PRIORITY_CLASS = 4;

  /** Prefetch */
  public static final short PREFETCH_PRIORITY_CLASS = 5;

  /** Anything less important than prefetch (redundant??) */
  public static final short PAUSED_PRIORITY_CLASS = 6;

  public static final short NUMBER_OF_PRIORITY_CLASSES =
      PAUSED_PRIORITY_CLASS - MAXIMUM_PRIORITY_CLASS + 1; // include 0 and max !!

  public static final short MINIMUM_FETCHABLE_PRIORITY_CLASS = PREFETCH_PRIORITY_CLASS;

  public static boolean isValidPriorityClass(int prio) {
    return !((prio < MAXIMUM_PRIORITY_CLASS) || (prio > PAUSED_PRIORITY_CLASS));
  }

  final BaseRequestThrottle throttle;
  final RunningAverage averageInputBytesPerRequest;
  final RunningAverage averageOutputBytesPerRequest;
  RequestScheduler sched;
  final NodeClientCore core;
  final NodeStats stats;
  private final boolean isInsert;
  private final boolean isSSK;
  final boolean realTime;

  /**
   * Creates a new starter for a specific flow (type and mode).
   *
   * @param node node client core used to access schedulers and executor
   * @param throttle adaptive throttle that provides per‑request delays
   * @param name base name used for diagnostics; mode suffix is appended
   * @param averageOutputBytesPerRequest running average of bytes sent per request
   * @param averageInputBytesPerRequest running average of bytes received per request
   * @param isInsert whether this starter handles inserts ({@code true}) or fetches ({@code false})
   * @param isSSK whether this starter handles SSK ({@code true}) or CHK ({@code false})
   * @param realTime whether this starter runs in real‑time mode
   */
  public RequestStarter(
      NodeClientCore node,
      BaseRequestThrottle throttle,
      String name,
      RunningAverage averageOutputBytesPerRequest,
      RunningAverage averageInputBytesPerRequest,
      boolean isInsert,
      boolean isSSK,
      boolean realTime) {
    this.core = node;
    this.stats = node.getNode().network().stats();
    this.throttle = throttle;
    this.name = name + (realTime ? " (realtime)" : " (bulk)");
    this.averageOutputBytesPerRequest = averageOutputBytesPerRequest;
    this.averageInputBytesPerRequest = averageInputBytesPerRequest;
    this.isInsert = isInsert;
    this.isSSK = isSSK;
    this.realTime = realTime;
  }

  void setScheduler(RequestScheduler sched) {
    this.sched = sched;
  }

  void start() {
    core.getNode().network().executor().execute(this, name);
  }

  final String name;

  /**
   * Returns a human‑readable name for diagnostics.
   *
   * @return the starter name including its mode suffix
   */
  @Override
  public String toString() {
    return name;
  }

  // Main worker loop. Grabs or waits for a request, applies throttling, and either
  // starts it or keeps it for a retry when NodeStats requests a temporary deferral.
  void realRun() {
    ChosenBlock req = null;
    long cycleTime = System.currentTimeMillis();
    while (true) {
      if (shouldDeferForOpennet()) {
        if (waitOneSecond()) return; // interrupted: avoid spin and let outer run() exit
        continue;
      }

      req = nextRequest(req);
      if (req == null) return; // interrupted while waiting

      assert (req.realTimeFlag == realTime);
      ProcessResult pr = processRequest(req, cycleTime);
      cycleTime = pr.cycleTime;
      // Drop only when the request was started or handled; keep it when deferred
      if (!pr.keepRequest) req = null;
    }
  }

  private ChosenBlock nextRequest(ChosenBlock current) {
    ChosenBlock r = ensureRequest(current);
    if (r != null) return r;
    return waitForRequest();
  }

  private ProcessResult processRequest(ChosenBlock req, long cycleTime) {
    if (prepareAndCheckRejection(req, cycleTime)) {
      // Temporarily rejected by NodeStats: keep the same request and retry after delay
      return new ProcessResult(System.currentTimeMillis(), true);
    }
    boolean started = startRequest(req);
    logIfNotCancelled(req, started);
    long nextCycle = (!req.localRequestOnly) ? System.currentTimeMillis() : cycleTime;
    return new ProcessResult(nextCycle, false);
  }

  private record ProcessResult(long cycleTime, boolean keepRequest) {}

  private boolean shouldDeferForOpennet() {
    OpennetManager om;
    return core.getNode().network().peers().countConnectedPeers() < 3
        && (om = core.getNode().network().opennet()) != null
        && System.currentTimeMillis() - om.getCreationTime() < MINUTES.toMillis(5);
  }

  private boolean waitOneSecond() {
    synchronized (this) {
      long millis = 1000L;
      long end = System.currentTimeMillis() + millis;
      long remaining = millis;
      while (remaining > 0) {
        try {
          wait(remaining);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          if (LOG.isDebugEnabled()) LOG.debug("One-second wait interrupted", e);
          return true; // signal interrupt to caller to avoid spin under opennet defer
        }
        // If we were notified (or spuriously woke) before the timeout, exit early so wakeUp()
        // remains responsive during opennet bootstrap.
        remaining = end - System.currentTimeMillis();
        if (remaining > 0) remaining = 0;
      }
      return false;
    }
  }

  @SuppressWarnings("java:S2142")
  private void applyThrottleDelay(long cycleTime) {
    long delay = throttle.getDelay();
    if (LOG.isDebugEnabled()) LOG.debug("Apply delay={} ms from {}", delay, throttle);
    long sleepUntil = cycleTime + delay;
    long now;
    do {
      now = System.currentTimeMillis();
      if (now < sleepUntil)
        try {
          Thread.sleep(sleepUntil - now);
          if (LOG.isDebugEnabled()) LOG.debug("Slept {} ms", sleepUntil - now);
        } catch (InterruptedException e) {
          // Swallow interrupt here so throttling resumes on subsequent iterations.
          // Do not re-set the interrupt flag; callers that need to exit on interrupt
          // should return from higher-level waits (e.g., waitForRequest/waitOneSecond).
          if (LOG.isDebugEnabled()) LOG.debug("Throttle delay interrupted", e);
          return;
        }
    } while (now < sleepUntil);
  }

  private RejectReason shouldReject(ChosenBlock req) {
    return stats.shouldRejectRequest(
        RequestAdmissionContext.of(
            true,
            isInsert,
            isSSK,
            true,
            false,
            null,
            false,
            Node.PREFER_INSERT_DEFAULT && isInsert,
            req.realTimeFlag,
            null));
  }

  private void logIfNotCancelled(ChosenBlock req, boolean started) {
    if (!started && !isCancelledTransient(req)) {
      LOG.info("No eligible request for {}", req);
    }
  }

  private boolean isCancelledTransient(ChosenBlock req) {
    return !req.isPersistent() && req.isCancelled();
  }

  private ChosenBlock ensureRequest(ChosenBlock current) {
    return current != null ? current : sched.grabRequest();
  }

  private ChosenBlock waitForRequest() {
    if (LOG.isDebugEnabled()) LOG.debug("Waiting for request...");
    synchronized (this) {
      ChosenBlock r = sched.grabRequest();
      while (r == null) {
        try {
          wait();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          if (LOG.isDebugEnabled()) LOG.debug("Wait for request interrupted", e);
          return null;
        }
        r = sched.grabRequest();
      }
      return r;
    }
  }

  private boolean prepareAndCheckRejection(ChosenBlock req, long cycleTime) {
    if (req.localRequestOnly) {
      stats.waitUntilNotOverloaded();
      return false;
    }
    applyThrottleDelay(cycleTime);
    return shouldReject(req) != null;
  }

  private boolean startRequest(ChosenBlock req) {
    if ((!req.isPersistent()) && req.isCancelled()) {
      req.onDumped();
      return false;
    }
    boolean failed =
        (req.key != null && !sched.addToFetching(req.key))
            || (((ChosenBlockImpl) req).request instanceof SendableInsert insert
                && !sched.addRunningInsert(insert, req.token.getKey()));
    if (failed) {
      req.onDumped();
      return false;
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Start request {} with priority {}", req, req.getPriority());
    core.getNode()
        .network()
        .executor()
        .execute(new SenderThread(req, req.key), "RequestStarter$SenderThread for " + req);
    return true;
  }

  /**
   * Runs the starter loop until interrupted.
   *
   * <p>Exits cleanly when the thread is interrupted. Any unexpected exceptions are logged and the
   * loop continues so isolated failures do not stop the starter.
   */
  @Override
  public void run() {
    while (true) {
      if (Thread.currentThread().isInterrupted()) {
        if (LOG.isDebugEnabled()) LOG.debug("RequestStarter interrupted; exiting");
        return;
      }
      try {
        realRun();
      } catch (Exception t) {
        LOG.error("Unhandled exception: {}", t, t);
      }
    }
  }

  private class SenderThread implements Runnable {

    private final ChosenBlock req;
    private final Key key;

    public SenderThread(ChosenBlock req, Key key) {
      this.req = req;
      this.key = key;
    }

    @Override
    public void run() {
      // Key may be null for inserts
      if (key != null) stats.reportOutgoingLocalRequestLocation(key.toNormalizedDouble());
      if (!req.send(core, sched)) {
        if (!((!req.isPersistent()) && req.isCancelled()))
          LOG.error("Send request failed for {}", req);
        else LOG.info("Send request skipped for {} - request was cancelled", req);
      }
      if (LOG.isDebugEnabled()) LOG.debug("Finished request {}", req);
    }
  }

  /**
   * Wakes threads that wait for new work.
   *
   * <p>LOCKING: do not hold the {@code RequestStarter} lock when calling this method; waking while
   * holding it can deadlock waiters attempting to reacquire the same monitor.
   */
  public void wakeUp() {
    synchronized (this) {
      notifyAll();
    }
  }

  /**
   * Computes an exclusion time for a candidate item.
   *
   * <p>Returns {@code Long.MAX_VALUE} when a persistent request for the same item is already
   * running or queued. For non‑inserts, delegates to {@link BaseSendableGet#getWakeupTime}.
   *
   * @param item candidate request item
   * @param context client context for computing wakeup time
   * @param now current time in milliseconds since epoch
   * @return exclusion delay in milliseconds, or a sentinel value as described above
   */
  @Override
  public long exclude(RandomGrabArrayItem item, ClientContext context, long now) {
    if (sched.isRunningOrQueuedPersistentRequest((SendableRequest) item)) {
      LOG.info("Exclude already running request {}", item);
      return Long.MAX_VALUE;
    }
    if (isInsert) return -1;
    if (!(item instanceof BaseSendableGet get)) {
      LOG.error("exclude() called with unsupported item {}", item);
      return -1;
    }
    return get.getWakeupTime(context, now);
  }
}
