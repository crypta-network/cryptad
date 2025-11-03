package network.crypta.client.async;

import java.lang.ref.WeakReference;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Objects;
import network.crypta.client.FetchContext;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.node.BaseSendableGet;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.Node;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestScheduler;
import network.crypta.node.RequestStarter;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableInsert;
import network.crypta.node.SendableRequest;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestItemKey;
import network.crypta.support.RandomGrabArray;
import network.crypta.support.RandomGrabArrayWithObject;
import network.crypta.support.RemoveRandom.RemoveRandomReturn;
import network.crypta.support.RemoveRandomParent;
import network.crypta.support.SectoredRandomGrabArray;
import network.crypta.support.SectoredRandomGrabArraySimple;
import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Global in-memory selector and scheduler-facing queue for client requests.
 *
 * <p>This component holds both transient and persistent requests in a tiered structure organized by
 * priority class, client, and logical request group. It exposes efficient operations to choose the
 * next {@link SendableRequest} to run and to track short-lived state such as cooldowns and
 * in-flight keys. Matching a fetched block back to interested listeners is handled elsewhere (see
 * the KeyListenerTracker code path); this class focuses strictly on selection and lightweight
 * bookkeeping and is not persistent.
 *
 * <p>Wakeup and cooldowns: Each node in the tree (priority, client, request) maintains a per-node
 * wakeup time. A positive value indicates the earliest time when it is worthwhile to revisit the
 * subtree. Values may be {@code Long.MAX_VALUE} while a key is actively fetching or when a request
 * is throttled by a cooldown (e.g., due to repeated fetches of the same key).
 *
 * <p>Locking and concurrency: All access to the tree—including the cooldown tracker—is guarded by
 * synchronization on the {@code ClientRequestSelector} instance. When a request completes we update
 * wakeup times bottom-up. When selecting a request we traverse top-down and may update wakeups
 * while backtracking. This ensures consistent views for competing scheduler threads at the cost of
 * coarse-grained locking.
 *
 * <ul>
 *   <li>Responsibilities: request registration, reclassification across priorities, selection, and
 *       tracking of in-flight keys/inserts.
 *   <li>Notable behaviors: recent-success bias for fetches, per-node wakeup propagation, and strict
 *       lock ordering to avoid deadlocks with other subsystems.
 * </ul>
 *
 * @see RequestStarter
 * @see SendableRequest
 * @see KeysFetchingLocally
 */
public class ClientRequestSelector implements KeysFetchingLocally {
  private static final Logger LOG = LoggerFactory.getLogger(ClientRequestSelector.class);
  private static final String PRIORITY = "Priority ";
  private static final String FOR = " for ";
  private static final String CHANGING_PRIORITY_NOT_RUNNING =
      "Changing priority but request not running {}";
  private static final String RECENT_SUCCESSES = "recentSuccesses";
  private static final String RUNNING_INSERTS = "runningInserts";
  private static final String KEYS_FETCHING = "keysFetching";

  final boolean isInsertScheduler;
  final boolean isSSKScheduler;
  final boolean isRTScheduler;

  final ClientRequestScheduler sched;

  // Root: SRGA of SRGAs (for a priority), descend by RequestClient.
  // Layer 1: SRGA of RGAs (for a RequestClient), descend by ClientRequestSchedulerGroup.
  // Layer 2: RGAs (for a ClientRequestSchedulerGroup), contain SendableRequest's.
  // Layer 3: SendableRequest's.

  static class ClientRequestRGANode
      extends SectoredRandomGrabArraySimple<RequestClient, ClientRequestSchedulerGroup> {
    /**
     * Creates a node that groups scheduler groups beneath a specific {@link RequestClient} within a
     * priority bucket.
     *
     * @param object the owning {@link RequestClient} represented by this node; must not be {@code
     *     null}
     * @param parent parent grab-array container that holds this node under a priority; may be
     *     {@code null} for the first insertion
     * @param root the selector that supplies cooldown and randomization policies; must not be
     *     {@code null}
     */
    public ClientRequestRGANode(
        RequestClient object, RemoveRandomParent parent, ClientRequestSelector root) {
      super(object, parent, root);
    }
  }

  static class RequestClientRGANode
      extends SectoredRandomGrabArray<RequestClient, ClientRequestRGANode> {
    /**
     * Creates the per-priority container that maps each {@link RequestClient} to its child {@link
     * ClientRequestRGANode}.
     *
     * @param parent parent grab-array container (higher level in the selector hierarchy); may be
     *     {@code null} when first created for a priority
     * @param root the selector instance coordinating wakeups and selection policies; must not be
     *     {@code null}
     */
    public RequestClientRGANode(RemoveRandomParent parent, ClientRequestSelector root) {
      super(parent, root);
    }
  }

  /** The base of the tree. */
  private final RequestClientRGANode[] priorities;

  /**
   * Ring buffer of recently successful {@link BaseSendableGet} operations.
   *
   * <p>The selector occasionally prefers a request that has succeeded very recently as a cheap
   * locality heuristic. This deque stores a bounded, most-recent-first history (currently up to 8
   * entries). It is only populated for fetch schedulers (not for insert schedulers) and is accessed
   * under internal synchronization on the deque instance.
   */
  protected final Deque<BaseSendableGet> recentSuccesses;

  ClientRequestSelector(
      boolean isInsertScheduler,
      boolean isSSKScheduler,
      boolean isRTScheduler,
      ClientRequestScheduler sched) {
    this.sched = sched;
    this.isInsertScheduler = isInsertScheduler;
    this.isSSKScheduler = isSSKScheduler;
    this.isRTScheduler = isRTScheduler;
    if (!isInsertScheduler) {
      keysFetching = new HashSet<>();
      transientRequestsWaitingForKeysFetching = new HashMap<>();
      runningInserts = null;
      recentSuccesses = new ArrayDeque<>();
    } else {
      keysFetching = null;
      runningInserts = new HashSet<>();
      recentSuccesses = null;
    }
    priorities = new RequestClientRGANode[RequestStarter.NUMBER_OF_PRIORITY_CLASSES];
  }

  // Static initializer intentionally omitted; placeholder removed.

  /**
   * All Key's we are currently fetching. Locally originated requests only, avoids some
   * complications with HTL, and also has the benefit that we can see stuff that's been scheduled on
   * a SenderThread but that thread hasn't started yet. Note: Both issues can be avoided: first we'd
   * get rid of the SenderThread and start the requests directly and asynchronously, secondly we'd
   * move this to node but only track keys we are fetching at max HTL. LOCKING: Always lock this
   * LAST.
   */
  private final HashSet<Key> keysFetching;

  private HashMap<Key, WeakReference<BaseSendableGet>[]> transientRequestsWaitingForKeysFetching;

  private final HashSet<SendableRequestItemKey> runningInserts;

  @SuppressWarnings("unchecked")
  private static WeakReference<BaseSendableGet>[] newWeakGetterArray() {
    // Centralize unchecked array creation for WeakReference<BaseSendableGet>[]
    return (WeakReference<BaseSendableGet>[]) new WeakReference<?>[1];
  }

  /**
   * Choose a priority to start requests from.
   *
   * @return The priority chosen or the time at which a priority will have requests to send.
   *     LOCKING: Synchronized because we may create new priorities. Both the cooldown queue and the
   *     RGA hierarchy, rooted at the priorities, use ClientRequestSelector lock.
   */
  private synchronized long choosePriority(
      int fuzz, RandomSource random, ClientContext context, long now) {
    long wakeupTime = Long.MAX_VALUE;
    short iteration = 0;
    while (iteration++ < RequestStarter.NUMBER_OF_PRIORITY_CLASSES + 1) {
      short priority = selectPriority(fuzz, random);
      RequestClientRGANode result = priorities[priority];
      long cooldownTime = (result == null) ? 0 : result.getWakeupTime(context, now);

      if (cooldownTime > 0) {
        wakeupTime = Math.min(wakeupTime, cooldownTime);
        logPriorityCooldown(priority, cooldownTime, now);
      } else if (priority <= RequestStarter.MINIMUM_FETCHABLE_PRIORITY_CLASS
          && result != null
          && !result.isEmpty()) {
        if (LOG.isDebugEnabled()) LOG.debug("using priority : {}", priority);
        return priority;
      } else {
        if (LOG.isDebugEnabled()) LOG.debug(PRIORITY + "{} is null (fuzz = {})", priority, fuzz);
      }

      // Don't return because first round may be higher with soft scheduling
      fuzz++;
    }

    // No available priority: return earliest wakeup time observed
    return wakeupTime;
  }

  private static short selectPriority(int fuzz, RandomSource random) {
    return fuzz < 0
        ? tweakedPrioritySelector[random.nextInt(tweakedPrioritySelector.length)]
        : prioritySelector[Math.abs(fuzz % prioritySelector.length)];
  }

  private static void logPriorityCooldown(short priority, long cooldownTime, long now) {
    if (!LOG.isDebugEnabled()) return;
    if (cooldownTime == Long.MAX_VALUE) {
      LOG.debug(PRIORITY + "{} is waiting until a request finishes or is empty", priority);
    } else {
      LOG.debug(
          PRIORITY + "{} is in cooldown for another {} {}",
          priority,
          (cooldownTime - now),
          TimeUtil.formatTime(cooldownTime - now));
    }
  }

  /**
   * Choose a request to run and create the ChosenBlock for it. A request chosen by
   * chooseRequestInner() may not be runnable (it may return null if the request is already
   * running), so we may need to try repeatedly. This is only necessary because many classes only
   * update their cooldown status when choosing a block to send, e.g. SplitFileInserter.
   */
  ChosenBlock chooseRequest(
      int fuzz,
      RandomSource random,
      OfferedKeysList offeredKeys,
      RequestStarter starter,
      boolean realTime,
      ClientContext context) {
    long now = System.currentTimeMillis();
    for (int i = 0; i < 5; i++) {
      SelectorReturn r =
          chooseRequestInner(fuzz, random, offeredKeys, starter, realTime, context, now);
      SendableRequest req = r.req;
      if (req == null) {
        if (r.wakeupTime != Long.MAX_VALUE && r.wakeupTime > now) {
          // Wake up later.
          sched.clientContext.ticker.queueTimedJob(sched::wakeStarter, r.wakeupTime - now);
        }
        continue;
      }
      if (isInsertScheduler && req instanceof SendableGet) {
        IllegalStateException e =
            new IllegalStateException(
                "removeFirstInner returned a SendableGet on an insert scheduler!!");
        req.internalError(e, sched, context, req.persistent());
        throw e;
      }
      ChosenBlock block = maybeMakeChosenRequest(req, context, now);
      if (block != null) return block;
    }
    return null;
  }

  /**
   * Build a {@code ChosenBlock} for a request if it is presently runnable.
   *
   * <p>This method validates that the provided {@link SendableRequest} is not cancelled, not in a
   * cooldown period, and currently eligible to choose a concrete token/key. When eligible, it asks
   * the request to select a {@link SendableRequestItem}, resolves the corresponding network {@link
   * Key} and optional {@link ClientKey}, and constructs a {@code ChosenBlock} carrying all flags
   * needed by the scheduler. No network I/O is performed here; selection is purely in-memory and
   * side‑effect free beyond reading request state.
   *
   * <p>Preconditions: {@code req} must belong to this selector kind (fetch vs insert). The caller
   * should pass a consistent {@link ClientContext} and the current wall clock {@code now} in
   * milliseconds. If selection races with a request transitioning into cooldown, the method may
   * return {@code null} to signal the caller to try another candidate.
   *
   * @param req the request to consider; ignored if {@code null} or cancelled
   * @param context execution context providing runtime collaborators; must not be {@code null}
   * @param now current time in milliseconds since the epoch used for cooldown checks
   * @return a fully populated {@code ChosenBlock} ready for dispatch, or {@code null} if the
   *     request is not currently runnable or could not choose a token
   */
  public ChosenBlock maybeMakeChosenRequest(SendableRequest req, ClientContext context, long now) {
    if (shouldSkipRequest(req, context, now)) return null;

    SendableRequestItem token = req.chooseKey(this, context);
    if (token == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Choose key returned null: {}", req);
      return null;
    }

    KeyAndClientKey keys = resolveKeys(req, token);
    RequestFlags flags = resolveRequestFlags(req);
    ChosenBlock ret =
        new ChosenBlockImpl(
            req,
            token,
            keys.key,
            keys.ckey,
            flags.localRequestOnly,
            flags.ignoreStore,
            flags.canWriteClientCache,
            flags.forkOnCacheable,
            flags.realTimeFlag,
            sched,
            req.persistent());
    if (LOG.isDebugEnabled()) LOG.debug("Created {}" + FOR + "{}", ret, req);
    return ret;
  }

  private boolean shouldSkipRequest(SendableRequest req, ClientContext context, long now) {
    if (req == null) return true;
    if (req.isCancelled()) {
      if (LOG.isDebugEnabled()) LOG.debug("Request is cancelled: {}", req);
      return true;
    }
    if (req.getWakeupTime(context, now) != 0) {
      // Race condition. We don't need to add a wake-up job. This shouldn't happen
      // because we only consider local requests of the same type?! Add logging and debug!
      if (LOG.isDebugEnabled()) LOG.debug("Request is in cooldown: {}", req);
      return true;
    }
    return false;
  }

  private KeyAndClientKey resolveKeys(SendableRequest req, SendableRequestItem token) {
    if (isInsertScheduler) {
      return new KeyAndClientKey(null, null);
    }
    Key key = ((BaseSendableGet) req).getNodeKey(token);
    ClientKey ckey = (req instanceof SendableGet get) ? get.getKey(token) : null;
    if (key != null && key.getRoutingKey() == null) throw new NullPointerException();
    return new KeyAndClientKey(key, ckey);
  }

  private RequestFlags resolveRequestFlags(SendableRequest req) {
    return switch (req) {
      case SendableGet sg -> {
        RequestFlags f = new RequestFlags();
        FetchContext ctx = sg.getContext();
        f.localRequestOnly = ctx.localRequestOnly;
        f.ignoreStore = ctx.ignoreStore;
        f.canWriteClientCache = ctx.canWriteClientCache;
        f.realTimeFlag = sg.realTimeFlag();
        f.forkOnCacheable = false;
        yield f;
      }
      case SendableInsert insert -> {
        RequestFlags f = new RequestFlags();
        f.localRequestOnly = insert.localRequestOnly();
        f.ignoreStore = false;
        f.canWriteClientCache = insert.canWriteClientCache();
        f.forkOnCacheable = insert.forkOnCacheable();
        f.realTimeFlag = req.realTimeFlag();
        yield f;
      }
      default -> {
        RequestFlags f = new RequestFlags();
        f.localRequestOnly = false;
        f.ignoreStore = false;
        f.canWriteClientCache = false;
        f.forkOnCacheable = Node.FORK_ON_CACHEABLE_DEFAULT;
        f.realTimeFlag = false;
        yield f;
      }
    };
  }

  private record KeyAndClientKey(Key key, ClientKey ckey) {}

  private static final class RequestFlags {
    boolean localRequestOnly;
    boolean ignoreStore;
    boolean canWriteClientCache;
    boolean forkOnCacheable;
    boolean realTimeFlag;
  }

  /**
   * Lightweight result of a selection attempt.
   *
   * <p>When a request is immediately available, {@link #req} is non-{@code null} and can be handed
   * off to build a {@code ChosenBlock}. When selection finds nothing runnable, {@link #req} is
   * {@code null} and {@link #wakeupTime} carries the earliest time at which another attempt may be
   * worthwhile. The type is immutable and intended for short-lived use by the scheduler.
   */
  public static class SelectorReturn {
    /**
     * The request selected by the chooser, or {@code null} when no request is immediately available
     * and {@link #wakeupTime} should be honored instead.
     */
    public final SendableRequest req;

    /**
     * When {@link #req} is {@code null}, the earliest time (milliseconds since the epoch) when the
     * caller should try selection again. {@code Long.MAX_VALUE} indicates no known earlier wakeup.
     */
    public final long wakeupTime;

    SelectorReturn(SendableRequest req) {
      this.req = req;
      this.wakeupTime = -1;
    }

    SelectorReturn(long wakeupTime) {
      this.wakeupTime = wakeupTime;
      this.req = null;
    }
  }

  /**
   * Choose a request to run. Does not check whether the SendableRequest is actually runnable at the
   * moment. The cooldown mechanism on the RGAs and SRGAs should ensure that it is usable most of
   * the time.
   *
   * @return Either a chosen request or the time at which we should try again if all priorities are
   *     waiting for requests to finish / cooldown periods to expire.
   */
  SelectorReturn chooseRequestInner(
      int fuzz,
      RandomSource random,
      OfferedKeysList offeredKeys,
      RequestStarter starter,
      boolean realTime,
      ClientContext context,
      long now) {
    // Priorities start at 0
    if (LOG.isDebugEnabled()) LOG.debug("removeFirst()");
    boolean tryOfferedKeys = offeredKeys != null && random.nextBoolean();
    SelectorReturn offeredFirst =
        maybeUseOfferedKeysFirst(tryOfferedKeys, offeredKeys, context, now);
    if (offeredFirst != null) return offeredFirst;

    long l = choosePriority(fuzz, random, context, now);
    if (l > Integer.MAX_VALUE) {
      if (LOG.isDebugEnabled())
        LOG.debug("No priority available for the next {}", TimeUtil.formatTime(l - now));
      return new SelectorReturn(l);
    }
    int choosenPriorityClass = (int) l;
    if (choosenPriorityClass == -1) {
      SelectorReturn offeredSecond =
          maybeUseOfferedKeysIfNotTried(tryOfferedKeys, offeredKeys, context, now);
      if (offeredSecond != null) return offeredSecond;
      if (LOG.isDebugEnabled()) LOG.debug("Nothing to do");
      // No requests queued at all.
      return new SelectorReturn(Long.MAX_VALUE);
    }

    return selectFromPriorities(choosenPriorityClass, starter, context, now, realTime, random);
  }

  private SelectorReturn selectFromPriorities(
      int startingPriority,
      RequestStarter starter,
      ClientContext context,
      long now,
      boolean realTime,
      RandomSource random) {
    long wakeupTime = Long.MAX_VALUE;
    for (int pr = startingPriority; pr <= RequestStarter.MINIMUM_FETCHABLE_PRIORITY_CLASS; pr++) {
      if (LOG.isDebugEnabled()) LOG.debug("Using priority {}", pr);
      RequestClientRGANode chosenTracker = priorities[pr];
      if (chosenTracker == null) {
        if (LOG.isDebugEnabled()) LOG.debug("No requests to run: chosen priority empty");
        continue; // Try next priority
      }

      PriorityScanResult res =
          scanPriorityForRequest(chosenTracker, pr, starter, context, now, realTime, random);
      if (res.req != null) return new SelectorReturn(res.req);
      if (res.nextWakeupTime > 0 && res.nextWakeupTime < wakeupTime)
        wakeupTime = res.nextWakeupTime;
    }
    if (LOG.isDebugEnabled()) LOG.debug("No requests to run");
    return new SelectorReturn(wakeupTime);
  }

  private SelectorReturn maybeUseOfferedKeysFirst(
      boolean tryOfferedKeys, OfferedKeysList offeredKeys, ClientContext context, long now) {
    if (tryOfferedKeys && offeredKeys.getWakeupTime(context, now) == 0)
      return new SelectorReturn(offeredKeys);
    return null;
  }

  private SelectorReturn maybeUseOfferedKeysIfNotTried(
      boolean tryOfferedKeys, OfferedKeysList offeredKeys, ClientContext context, long now) {
    if (!tryOfferedKeys && offeredKeys != null && offeredKeys.getWakeupTime(context, now) == 0)
      return new SelectorReturn(offeredKeys);
    return null;
  }

  private record PriorityScanResult(SendableRequest req, long nextWakeupTime) {

    static PriorityScanResult found(SendableRequest req) {
      return new PriorityScanResult(req, Long.MAX_VALUE);
    }

    static PriorityScanResult none(long wakeupTime) {
      return new PriorityScanResult(null, wakeupTime);
    }
  }

  private PriorityScanResult scanPriorityForRequest(
      RequestClientRGANode chosenTracker,
      int choosenPriorityClass,
      RequestStarter starter,
      ClientContext context,
      long now,
      boolean realTime,
      RandomSource random) {
    while (true) {
      PriorityScanResult cooldown =
          checkAndReturnIfInCooldown(chosenTracker, choosenPriorityClass, context, now);
      if (cooldown != null) return cooldown;

      if (LOG.isDebugEnabled()) LOG.debug("Got priority tracker {}", chosenTracker);
      RemoveRandomReturn val = removeRandomThreadSafe(chosenTracker, starter, context, now);
      PriorityScanResult early = handleNullItem(val, choosenPriorityClass, now);
      if (early != null) return early;

      SendableRequest req = (SendableRequest) val.item;
      if (req == null) {
        // Defensive: handleNullItem should have returned early when item is null
        return PriorityScanResult.none(Long.MAX_VALUE);
      }
      if (handlePriorityMismatchAndReclassify(chosenTracker, req, choosenPriorityClass, context))
        continue; // Try again on this priority

      // Maybe use a recently succeeded request instead
      req = maybePreferRecentSuccess(req, choosenPriorityClass, random, context, now);

      // Now we have chosen a request.
      if (LOG.isDebugEnabled())
        LOG.debug(
            "removeFirst() returning {} (prio {}, client {}, client-req {})",
            req,
            req.getPriorityClass(),
            req.getClient(),
            req.getClientRequest());
      if (LOG.isDebugEnabled())
        LOG.debug("removeFirst() returning {} of {}", req, req.getClientRequest());
      assert (req.realTimeFlag() == realTime);
      return PriorityScanResult.found(req);
    }
  }

  private PriorityScanResult checkAndReturnIfInCooldown(
      RequestClientRGANode chosenTracker,
      int choosenPriorityClass,
      ClientContext context,
      long now) {
    long cooldownTime = chosenTracker.getWakeupTime(context, now);
    if (cooldownTime > 0) {
      if (LOG.isInfoEnabled()) {
        LOG.info(
            "Priority {} is in cooldown for another {} {}",
            choosenPriorityClass,
            cooldownTime - now,
            TimeUtil.formatTime(cooldownTime - now));
      }
      return PriorityScanResult.none(cooldownTime);
    }
    return null;
  }

  private PriorityScanResult handleNullItem(
      RemoveRandomReturn val, int choosenPriorityClass, long now) {
    if (val == null) {
      LOG.info(
          PRIORITY + "{} returned null - nothing to schedule, should remove priority",
          choosenPriorityClass);
      return PriorityScanResult.none(Long.MAX_VALUE);
    }

    if (val.item == null) {
      if (val.wakeupTime == -1)
        LOG.info(
            PRIORITY
                + "{} returned cooldown time of -1 - nothing to schedule, should remove priority",
            choosenPriorityClass);
      else {
        if (LOG.isInfoEnabled()) {
          LOG.info(
              PRIORITY + "{} returned cooldown time of {} = {}",
              choosenPriorityClass,
              val.wakeupTime - now,
              TimeUtil.formatTime(val.wakeupTime - now));
        }
      }
      return PriorityScanResult.none(val.wakeupTime);
    }
    return null;
  }

  private boolean handlePriorityMismatchAndReclassify(
      RequestClientRGANode chosenTracker,
      SendableRequest req,
      int choosenPriorityClass,
      ClientContext context) {
    if (req.getPriorityClass() != choosenPriorityClass) {
      logWrongPriority(req, choosenPriorityClass);
      reclassifyRequest(chosenTracker, req, context);
      innerRegister(req, context);
      return true;
    }
    return false;
  }

  private RemoveRandomReturn removeRandomThreadSafe(
      RequestClientRGANode chosenTracker, RequestStarter starter, ClientContext context, long now) {
    synchronized (this) {
      // We must hold the overall lock, just as in addToGrabArrays.
      // This is important for keeping the cooldown tracker consistent amongst other
      // things: We can get a race condition between thread A reading the tree,
      // finding nothing and setCachedWakeup(), and thread B waking up a request,
      // resulting in the request not being accessible.
      return chosenTracker.removeRandom(starter, context, now);
    }
  }

  private static void logWrongPriority(SendableRequest req, int chosenPriorityClass) {
    LOG.info(
        "In wrong priority class: {} (req.prio={} but chosen={})",
        req,
        req.getPriorityClass(),
        chosenPriorityClass);
  }

  private void reclassifyRequest(
      RequestClientRGANode chosenTracker, SendableRequest req, ClientContext context) {
    ClientRequestRGANode clientGrabber = chosenTracker.getGrabber(req.getClient());
    if (clientGrabber != null) {
      RandomGrabArray baseRGA = clientGrabber.getGrabber(req.getSchedulerGroup());
      if (baseRGA != null) {
        // Must synchronize to avoid nasty race conditions with cooldown.
        synchronized (this) {
          baseRGA.remove(req, context);
        }
      } // Okay, it's been removed already. Cool.
    } else {
      LOG.error(
          "Could not find client grabber for client {} from {}", req.getClient(), chosenTracker);
    }
  }

  private SendableRequest maybePreferRecentSuccess(
      SendableRequest req,
      int choosenPriorityClass,
      RandomSource random,
      ClientContext context,
      long now) {
    if (isInsertScheduler) return req;
    BaseSendableGet altReq = pollRecentSuccessMaybe(random);
    if (!isAltValid(altReq, context, now)) return req;
    if (altReq == req) return req;
    return decideBetweenAltAndReq(req, choosenPriorityClass, altReq);
  }

  private BaseSendableGet pollRecentSuccessMaybe(RandomSource random) {
    BaseSendableGet altReq = null;
    Deque<BaseSendableGet> rs = Objects.requireNonNull(recentSuccesses, RECENT_SUCCESSES);
    synchronized (rs) {
      if (!rs.isEmpty() && random.nextBoolean()) {
        altReq = rs.poll();
      }
    }
    return altReq;
  }

  private boolean isAltValid(BaseSendableGet altReq, ClientContext context, long now) {
    if (altReq == null) return false;
    if (altReq.isCancelled()) {
      if (LOG.isDebugEnabled()) LOG.debug("Ignoring cancelled recently succeeded item {}", altReq);
      return false;
    }
    long cooldown = altReq.getWakeupTime(context, now);
    if (cooldown != 0) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Ignoring recently succeeded item, cooldown time = {}{}",
            cooldown,
            (cooldown > 0) ? " (" + TimeUtil.formatTime(cooldown - now) + ")" : "");
      }
      return false;
    }
    return true;
  }

  private SendableRequest decideBetweenAltAndReq(
      SendableRequest req, int choosenPriorityClass, BaseSendableGet altReq) {
    int prio = altReq.getPriorityClass();
    if (prio <= choosenPriorityClass) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Recently succeeded (transient) req {} (prio={}) is better than {} (prio={}), using"
                + " that",
            altReq,
            altReq.getPriorityClass(),
            req,
            req.getPriorityClass());
      // Don't need to reregister, because removeRandom doesn't actually remove!
      return altReq;
    } else {
      if (LOG.isDebugEnabled())
        LOG.debug("Chosen req {} is better, reregistering recently succeeded {}", req, altReq);
      Deque<BaseSendableGet> rs = Objects.requireNonNull(recentSuccesses, RECENT_SUCCESSES);
      synchronized (rs) {
        rs.add(altReq);
      }
      return req;
    }
  }

  private static final short[] tweakedPrioritySelector = {
    RequestStarter.MAXIMUM_PRIORITY_CLASS,
    RequestStarter.MAXIMUM_PRIORITY_CLASS,
    RequestStarter.MAXIMUM_PRIORITY_CLASS,
    RequestStarter.MAXIMUM_PRIORITY_CLASS,
    RequestStarter.MAXIMUM_PRIORITY_CLASS,
    RequestStarter.MAXIMUM_PRIORITY_CLASS,
    RequestStarter.MAXIMUM_PRIORITY_CLASS,
    RequestStarter.INTERACTIVE_PRIORITY_CLASS,
    RequestStarter.INTERACTIVE_PRIORITY_CLASS,
    RequestStarter.INTERACTIVE_PRIORITY_CLASS,
    RequestStarter.INTERACTIVE_PRIORITY_CLASS,
    RequestStarter.INTERACTIVE_PRIORITY_CLASS,
    RequestStarter.INTERACTIVE_PRIORITY_CLASS,
    RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
    RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
    RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
    RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
    RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
    RequestStarter.UPDATE_PRIORITY_CLASS,
    RequestStarter.UPDATE_PRIORITY_CLASS,
    RequestStarter.UPDATE_PRIORITY_CLASS,
    RequestStarter.UPDATE_PRIORITY_CLASS,
    RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
    RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
    RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
    RequestStarter.PREFETCH_PRIORITY_CLASS,
    RequestStarter.PREFETCH_PRIORITY_CLASS
  };
  private static final short[] prioritySelector = {
    RequestStarter.MAXIMUM_PRIORITY_CLASS,
    RequestStarter.INTERACTIVE_PRIORITY_CLASS,
    RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
    RequestStarter.UPDATE_PRIORITY_CLASS,
    RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
    RequestStarter.PREFETCH_PRIORITY_CLASS
  };

  /**
   * Mark a key as actively being fetched by this node.
   *
   * <p>This tracks locally originated fetches only, enabling fast duplicate suppression and
   * efficient wakeups for transient requests waiting on the same key. Callers must only add keys
   * that are about to be scheduled; removal is handled via {@link #removeFetchingKey(Key)} when the
   * fetch completes or is abandoned.
   *
   * @param key the network {@link Key} to record as in-flight; must not be {@code null}
   * @return {@code true} if the key was added, or {@code false} when it was already present
   */
  public boolean addToFetching(Key key) {
    HashSet<Key> kf = Objects.requireNonNull(keysFetching, KEYS_FETCHING);
    synchronized (kf) {
      boolean retval = kf.add(key);
      if (!retval) {
        LOG.info("Already in keysFetching: {}", key);
      } else {
        if (LOG.isDebugEnabled()) LOG.debug("Added to keysFetching: {}", key);
      }
      return retval;
    }
  }

  /**
   * Returns whether {@code key} is currently being fetched by a locally originated request and, if
   * so, optionally registers a transient waiter to be woken when the fetch completes.
   *
   * <p>Synchronization: This implementation synchronizes on an internal set that tracks in-flight
   * keys. If {@code getterWaiting} is non-{@code null} and the key is already in flight, a weak
   * reference to the getter is recorded so the request can be woken when the key finishes.
   *
   * @param key the key to test for local in-flight status; must not be {@code null}
   * @param getterWaiting optional requester to register for wakeup when an existing fetch
   *     completes; may be {@code null}
   * @return {@code true} if the key is already fetching locally; otherwise {@code false}
   */
  @Override
  public boolean hasKey(Key key, BaseSendableGet getterWaiting) {
    if (keysFetching == null) {
      throw new NullPointerException();
    }
    synchronized (keysFetching) {
      boolean ret = keysFetching.contains(key);
      if (!ret) return false;
      // It is being fetched. Add the BaseSendableGet to the wait list so it gets woken up when the
      // request finishes.
      if (getterWaiting != null) {
        WeakReference<BaseSendableGet>[] waiting = transientRequestsWaitingForKeysFetching.get(key);
        if (waiting == null) {
          WeakReference<BaseSendableGet>[] single = newWeakGetterArray();
          single[0] = new WeakReference<>(getterWaiting);
          transientRequestsWaitingForKeysFetching.put(key, single);
        } else {
          for (WeakReference<BaseSendableGet> ref : waiting) {
            if (ref.get() == getterWaiting) return true;
          }
          WeakReference<BaseSendableGet>[] newWaiting = Arrays.copyOf(waiting, waiting.length + 1);
          newWaiting[waiting.length] = new WeakReference<>(getterWaiting);
          transientRequestsWaitingForKeysFetching.put(key, newWaiting);
        }
      }
      return true;
    }
  }

  /**
   * Remove a key from the in-flight fetch set and wake any transient waiters.
   *
   * <p>All transient {@link BaseSendableGet} instances registered as waiting for {@code key} are
   * signaled by clearing their wakeup time in the current {@link ClientContext}. This method is
   * idempotent; removing a key that is no longer tracked has no effect.
   *
   * <p>LOCKING: Caller should hold as few locks as possible to avoid lock inversions with the
   * internal selector structures.
   *
   * @param key the fetched {@link Key} to clear from tracking; ignored when {@code null}
   */
  public void removeFetchingKey(final Key key) {
    WeakReference<BaseSendableGet>[] transientWaiting;
    if (LOG.isDebugEnabled()) LOG.debug("Removing from keysFetching: {}", key);
    if (key != null) {
      HashSet<Key> kf = Objects.requireNonNull(keysFetching, KEYS_FETCHING);
      synchronized (kf) {
        kf.remove(key);
        transientWaiting = this.transientRequestsWaitingForKeysFetching.remove(key);
      }
      if (transientWaiting != null) {
        for (WeakReference<BaseSendableGet> ref : transientWaiting) {
          BaseSendableGet get = ref.get();
          if (get == null) continue;
          get.clearWakeupTime(sched.getContext());
        }
      }
    }
  }

  /**
   * Returns whether the given insert {@code token} is currently executing on this node.
   *
   * <p>The check is local to the insert scheduler and is synchronized on the internal set that
   * tracks running inserts. Use to avoid duplicate low-level work for the same token.
   *
   * @param token identifier of the low-level insert operation to check; must not be {@code null}
   * @return {@code true} if the token is recorded as running; otherwise {@code false}
   */
  @Override
  public boolean hasInsert(SendableRequestItemKey token) {
    HashSet<SendableRequestItemKey> ri = Objects.requireNonNull(runningInserts, RUNNING_INSERTS);
    synchronized (ri) {
      return ri.contains(token);
    }
  }

  /**
   * Register that an insert token is currently executing to prevent duplicate work.
   *
   * <p>This set is local to the insert scheduler. A return value of {@code false} indicates that a
   * concurrent insert for the same {@code token} is already running and the caller should refrain
   * from starting a duplicate.
   *
   * @param token unique identifier of the low-level insert operation; must not be {@code null}
   * @return {@code true} if the token was recorded successfully; {@code false} if it already
   *     existed
   */
  public boolean addRunningInsert(SendableRequestItemKey token) {
    HashSet<SendableRequestItemKey> ri = Objects.requireNonNull(runningInserts, RUNNING_INSERTS);
    synchronized (ri) {
      boolean retval = ri.add(token);
      if (!retval) {
        // This shouldn't happen often, because the chooseBlock()'s should check for it...
        LOG.error("Already in runningInserts: {}", token);
      } else {
        if (LOG.isDebugEnabled()) LOG.debug("Added to runningInserts: {}", token);
      }
      return retval;
    }
  }

  /**
   * Clear the running state for an insert token once it completes or fails.
   *
   * @param token identifier previously passed to {@link #addRunningInsert(SendableRequestItemKey)}
   */
  public void removeRunningInsert(SendableRequestItemKey token) {
    if (LOG.isDebugEnabled()) LOG.debug("Removing from runningInserts: {}", token);
    HashSet<SendableRequestItemKey> ri = Objects.requireNonNull(runningInserts, RUNNING_INSERTS);
    synchronized (ri) {
      ri.remove(token);
    }
  }

  /**
   * Performs a local routing probe to determine whether sending a request for {@code key} would be
   * rejected due to a recent failure.
   *
   * <p>This implementation delegates to the {@link Node}'s client core. The returned value is a
   * non-positive number when the request can proceed immediately; otherwise it is an absolute
   * wakeup time (milliseconds since the epoch) after which a retry may be attempted.
   *
   * @param key the key to evaluate for recent failures; must not be {@code null}
   * @param realTime when {@code true}, apply real-time heuristics; otherwise use bulk heuristics
   * @return a non-positive value when immediately sendable; otherwise an absolute wakeup timestamp
   */
  @Override
  public long checkRecentlyFailed(Key key, boolean realTime) {
    Node node = sched.getNode();
    return node.getClientCore().checkRecentlyFailed(key, realTime);
  }

  /**
   * Add a request (or insert) to the request selection tree.
   *
   * @param priorityClass The priority of the request.
   * @param client Label object indicating which larger group of requests this request belongs to
   *     (e.g. the global queue, or an FCP client), and whether it is persistent.
   * @param cr The high-level request that this single block request is part of. E.g. a fetch for a
   *     single key may download many blocks in a splitfile; an insert for a large freesite is
   *     considered a single {@link ClientRequester}.
   * @param req A single SendableRequest object which is one or more low-level requests. E.g. it can
   *     be an insert of a single block, or it can be a request or insert for a single segment
   *     within a splitfile.
   * @param context The client context object, which contains links to all the important objects
   *     that are not persisted in the database, e.g. executors, temporary filename generator, etc.
   */
  void addToGrabArray(
      short priorityClass,
      RequestClient client,
      ClientRequestSchedulerGroup cr,
      SendableRequest req,
      ClientContext context) {
    if ((priorityClass > RequestStarter.PAUSED_PRIORITY_CLASS)
        || (priorityClass < RequestStarter.MAXIMUM_PRIORITY_CLASS))
      throw new IllegalStateException(
          "Invalid priority: "
              + priorityClass
              + " - range is "
              + RequestStarter.MAXIMUM_PRIORITY_CLASS
              + " (most important) to "
              + RequestStarter.PAUSED_PRIORITY_CLASS
              + " (least important)");
    // Client
    synchronized (this) {
      ClientRequestRGANode requestGrabber = makeSRGAForClient(priorityClass, client, context);
      requestGrabber.add(cr, req, context);
    }
    sched.wakeStarter();
  }

  private ClientRequestRGANode makeSRGAForClient(
      short priorityClass, RequestClient client, ClientContext context) {
    RequestClientRGANode clientGrabber = priorities[priorityClass];
    if (clientGrabber == null) {
      clientGrabber = new RequestClientRGANode(null, this);
      priorities[priorityClass] = clientGrabber;
      if (LOG.isDebugEnabled())
        LOG.debug("Registering client tracker for priority {} : {}", priorityClass, clientGrabber);
    }
    // Request
    ClientRequestRGANode requestGrabber = clientGrabber.getGrabber(client);
    if (requestGrabber == null) {
      requestGrabber = new ClientRequestRGANode(client, clientGrabber, this);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Creating new grabber: {}" + FOR + "{} from {} : prio={}",
            requestGrabber,
            client,
            clientGrabber,
            priorityClass);
      clientGrabber.addGrabber(client, requestGrabber, context);
      clientGrabber.clearWakeupTime(context);
    }
    return requestGrabber;
  }

  /**
   * Re-register an existing logical request under a new priority class.
   *
   * <p>Moving a request between priority classes involves removing its scheduler group from the old
   * priority’s RGA hierarchy and inserting it under the new priority, preserving client and group
   * structure. If the request is not currently tracked (no structures exist at the old priority),
   * the method returns silently. The {@code lock} parameter is accepted for API compatibility and
   * ignored; caller synchronization should avoid holding unrelated locks during this operation.
   *
   * @param request the high-level client request being moved; must not be {@code null}
   * @param lock unused parameter retained for compatibility; may be {@code null}
   * @param context execution context used to manipulate selector structures; must not be {@code
   *     null}
   * @param oldPrio the prior priority class of {@code request}; used to locate existing structures
   */
  public void reregisterAll(
      ClientRequester request, RequestScheduler lock, ClientContext context, short oldPrio) {
    // Parameter 'lock' is intentionally unused; kept for API compatibility.
    if (lock != null && LOG.isTraceEnabled()) {
      LOG.trace("Ignoring lock parameter {}", lock);
    }
    RequestClient client = request.getClient();
    short newPrio = request.getPriorityClass();
    if (newPrio == oldPrio) {
      LOG.error("Changing priority from {} to {}" + FOR + "{}", oldPrio, newPrio, request);
      return;
    }
    ClientRequestSchedulerGroup group = request.getSchedulerGroup();
    synchronized (this) {
      // First by priority
      RequestClientRGANode clientGrabber = priorities[oldPrio];
      if (clientGrabber == null) {
        // Normal as most of the schedulers aren't relevant to any given insert/request.
        if (LOG.isDebugEnabled()) LOG.debug(CHANGING_PRIORITY_NOT_RUNNING, request);
        return;
      }
      // Then by RequestClient
      ClientRequestRGANode requestGrabber = clientGrabber.getGrabber(client);
      if (requestGrabber == null) {
        if (LOG.isDebugEnabled()) LOG.debug(CHANGING_PRIORITY_NOT_RUNNING, request);
        return;
      }
      RandomGrabArrayWithObject<ClientRequestSchedulerGroup> rga = requestGrabber.getGrabber(group);
      if (rga == null) {
        if (LOG.isDebugEnabled()) LOG.debug(CHANGING_PRIORITY_NOT_RUNNING, request);
        return;
      }
      requestGrabber.maybeRemove(rga, context);
      requestGrabber = makeSRGAForClient(newPrio, client, context);
      if (requestGrabber.getGrabber(group) != null) {
        LOG.error(
            "RGA already exists for {} : {} but want to insert {}",
            request,
            requestGrabber.getGrabber(group),
            rga,
            new Exception("error"));
        requestGrabber.maybeRemove(rga, context);
      }
      requestGrabber.addGrabber(group, rga, context);
    }
  }

  /**
   * Count the total number of keys represented by all queued requests across priorities.
   *
   * <p>Logs a human-readable summary by priority, client, and group, then returns the total key
   * count observed. Intended for diagnostics and monitoring rather than for tight loops.
   *
   * @param context execution context for accessing request internals; must not be {@code null}
   * @return the total number of keys (not requests) currently queued in the selector
   */
  public synchronized long countQueuedRequests(ClientContext context) {
    long total = 0;
    for (int i = 0; i < priorities.length; i++) {
      total += printAndCountPriority(i, priorities[i], context);
    }
    return total;
  }

  private long printAndCountPriority(int index, RequestClientRGANode prio, ClientContext context) {
    if (prio == null || prio.isEmpty()) {
      LOG.info("{}{} : empty", PRIORITY, index);
      return 0;
    }
    LOG.info("{}{} : {}", PRIORITY, index, prio.size());
    LOG.info("Clients: {}{}{}", prio.size(), FOR, prio);
    long total = 0;
    for (int k = 0; k < prio.size(); k++) {
      RequestClient client = prio.getClient(k);
      total += printAndCountClient(prio, k, client, context);
    }
    return total;
  }

  private long printAndCountClient(
      RequestClientRGANode prio, int clientIndex, RequestClient client, ClientContext context) {
    LOG.info("Client {} : {}", clientIndex, client);
    ClientRequestRGANode requestGrabber = prio.getGrabber(client);
    LOG.info("SRGA for client: {}", requestGrabber);
    long total = 0;
    for (int l = 0; l < requestGrabber.size(); l++) {
      ClientRequestSchedulerGroup cr = requestGrabber.getClient(l);
      total += printAndCountGroup(requestGrabber, l, cr, context);
    }
    return total;
  }

  private long printAndCountGroup(
      ClientRequestRGANode requestGrabber,
      int requestIndex,
      ClientRequestSchedulerGroup cr,
      ClientContext context) {
    LOG.info("Request {} : {}", requestIndex, cr);
    RandomGrabArray rga = requestGrabber.getGrabber(cr);
    LOG.info("Queued SendableRequests: {} on {}", rga.size(), rga);
    long sendable = 0;
    long all = 0;
    for (int m = 0; m < rga.size(); m++) {
      SendableRequest req = (SendableRequest) rga.get(m);
      if (req == null) continue;
      sendable += req.countSendableKeys(context);
      all += req.countAllKeys(context);
    }
    LOG.info("Sendable keys: {} all keys {} diff {}", sendable, all, (all - sendable));
    return all;
  }

  /**
   * Register a {@link SendableRequest} with this selector at its current priority.
   *
   * <p>The request must match the selector type (fetch vs insert). After validation, the method
   * inserts the request into the per-priority, per-client hierarchy and wakes the starter.
   *
   * @param req the request to register; must not be {@code null}
   * @param context execution context used to update selector structures; must not be {@code null}
   */
  void innerRegister(SendableRequest req, ClientContext context) {
    if (isInsertScheduler && req instanceof BaseSendableGet)
      throw new IllegalArgumentException("Adding a SendableGet to an insert scheduler!!");
    if ((!isInsertScheduler) && req instanceof SendableInsert)
      throw new IllegalArgumentException("Adding a SendableInsert to a request scheduler!!");
    if (isInsertScheduler != req.isInsert())
      throw new IllegalArgumentException(
          "Request isInsert="
              + req.isInsert()
              + " but my isInsertScheduler="
              + isInsertScheduler
              + "!!");
    short prio = req.getPriorityClass();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Still registering {} at prio {}" + FOR + "{} ssk={} insert={}",
          req,
          prio,
          req.getClientRequest(),
          this.isSSKScheduler,
          this.isInsertScheduler);
    addToGrabArray(prio, req.getClient(), req.getSchedulerGroup(), req, context);
    if (LOG.isDebugEnabled()) LOG.debug("Registered {} on prioclass={}", req, prio);
  }

  /**
   * Record that a fetch request succeeded, updating recent-success heuristics.
   *
   * <p>No-op for insert schedulers or cancelled requests. Maintains a bounded history used to
   * occasionally prioritize requests that recently fetched successfully.
   *
   * @param succeeded the successful {@link BaseSendableGet}; ignored if cancelled
   */
  public void succeeded(BaseSendableGet succeeded) {
    // Do nothing.
    // Keep a list of recently succeeded ClientRequester's.
    if (isInsertScheduler) return;
    if (succeeded.isCancelled()) return;
    // Don't bother with getCooldownTime at this point.
    if (LOG.isDebugEnabled()) LOG.debug("Recording successful fetch from {}", succeeded);
    Deque<BaseSendableGet> rs = Objects.requireNonNull(recentSuccesses, RECENT_SUCCESSES);
    synchronized (rs) {
      while (rs.size() >= 8) rs.pollFirst();
      rs.add(succeeded);
    }
  }

  /**
   * Trigger the scheduler to re-run selection outside internal locks.
   *
   * <p>Posts a task to the main executor that wakes the {@link ClientRequestScheduler} starter,
   * avoiding potential lock inversions.
   *
   * @param context the client context providing the executor to schedule the wakeup
   */
  public void wakeUp(ClientContext context) {
    // Break out of locks. Can be called within RGAs etc.!
    context.getMainExecutor().execute(sched::wakeStarter);
  }
}
