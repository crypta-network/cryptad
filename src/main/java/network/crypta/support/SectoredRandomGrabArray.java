package network.crypta.support;

import java.util.Arrays;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestSelector;
import network.crypta.client.async.RequestSelectionTreeNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A sectorized, group-fair random selector over child {@link RemoveRandomWithObject} containers.
 *
 * <p>This node organizes children by an associated "client" (or grouping key) so that each client
 * has an equal chance of being selected regardless of how many requests that client holds. In other
 * words, selection is uniform over clients first, and only then over a client's own items. The
 * structure is not persistent and is reconstructed on restart.
 *
 * <p>Locking: There is a single lock for the entire selection tree — the {@link
 * network.crypta.client.async.ClientRequestSelector}. Callers must synchronize on that lock before
 * invoking any method on SRGA/RGA nodes to keep internal invariants consistent. See the related
 * types for additional details.
 *
 * <p>Complexity and implementation notes: Many operations are {@code O(n)} and favor clarity over
 * optimal asymptotics due to historical constraints. The structure lives entirely in memory; memory
 * pressure is mitigated because there is only one queued object per splitfile. Future work may
 * streamline the algorithms without changing externally observable behavior.
 *
 * @param <T> the type of the grouping object ("client") associated with each child
 * @param <C> the type of child container stored under this node; must implement {@link
 *     RemoveRandomWithObject} for {@code T}
 */
public class SectoredRandomGrabArray<T, C extends RemoveRandomWithObject<T>>
    implements RemoveRandom, RemoveRandomParent, RequestSelectionTreeNode {

  private static final Logger LOG = LoggerFactory.getLogger(SectoredRandomGrabArray.class);

  /**
   * Maximum number of consecutive excluded child arrays tolerated in the limited fast path before
   * bailing out to the caller (which typically retries or falls back to an exhaustive scan).
   */
  private static final int MAX_EXCLUDED = 10;

  // No static initialization required.

  private RemoveRandomWithObject<T>[] grabArrays;
  private T[] grabClients;
  private RemoveRandomParent parent;

  /**
   * Shared selector root used as the synchronization monitor for this node (and siblings).
   *
   * <p>All public/protected methods in this class synchronize on this object. Callers should avoid
   * holding other locks when entering this API to prevent deadlocks.
   */
  protected final ClientRequestSelector root;

  // Earliest absolute time (epoch millis) to try selection again; 0 means ready now.
  private long wakeupTime;

  /**
   * Creates an empty sectorized selector.
   *
   * <p>Threading: All mutating and query operations synchronize on {@code root}. The same instance
   * must be shared across the selection tree.
   *
   * @param parent the parent used for wakeup propagation and pruning; may be {@code null}
   * @param root the shared selector root that acts as the monitor for synchronization; must not be
   *     {@code null}
   */
  public SectoredRandomGrabArray(RemoveRandomParent parent, ClientRequestSelector root) {
    grabClients = newClientArray(0);
    grabArrays = newGrabberArray(0);
    this.parent = parent;
    this.root = root;
  }

  /**
   * Adds a new child pair to the end of the dense prefix.
   *
   * <p>Identity semantics apply: clients are compared with {@code ==} within this class.
   *
   * @param client the grouping object associated with {@code rga}
   * @param rga the child container associated with {@code client}
   */
  protected void addElement(T client, C rga) {
    synchronized (root) {
      final int len = grabArrays.length;

      grabArrays = Arrays.copyOf(grabArrays, len + 1);
      grabArrays[len] = rga;

      grabClients = Arrays.copyOf(grabClients, len + 1);
      grabClients[len] = client;
    }
  }

  /**
   * Returns the index of the given client by identity, or {@code -1} if absent.
   *
   * <p>Note: Comparison uses reference equality, not {@code equals()}.
   *
   * @param client the client to search for
   * @return zero-based index, or {@code -1} when not present
   */
  protected int haveClient(T client) {
    synchronized (root) {
      for (int i = 0; i < grabClients.length; i++) {
        if (grabClients[i] == client) return i;
      }
      return -1;
    }
  }

  /**
   * Returns the child container associated with the given client, or {@code null} if not present.
   *
   * @param client the grouping object used as lookup key (compared by identity)
   * @return the child container, or {@code null} if no child exists for the given client
   */
  public C getGrabber(T client) {
    synchronized (root) {
      int idx = haveClient(client);
      if (idx == -1) return null;
      else return castGrabber(grabArrays[idx]);
    }
  }

  /**
   * Returns the client object stored at the provided index.
   *
   * <p>No bounds checks are performed.
   *
   * @param x zero-based index into the internal client array
   * @return the client at {@code x}
   */
  public T getClient(int x) {
    synchronized (root) {
      return grabClients[x];
    }
  }

  /**
   * Adds a child container for the given client.
   *
   * <p>The container's {@link RemoveRandomWithObject#getObject()} must be the same instance as the
   * {@code client} argument. On success this method clears the stored wakeup time on this node (and
   * parents) to prompt re-evaluation by the scheduler.
   *
   * @param client the grouping object to associate with the child; compared by identity
   * @param requestGrabber the child container to insert
   * @param context client execution context used for wakeup propagation; may be {@code null}
   * @throws IllegalArgumentException if the child's associated object is not {@code client}
   */
  public void addGrabber(T client, C requestGrabber, ClientContext context) {
    synchronized (root) {
      if (requestGrabber.getObject() != client)
        throw new IllegalArgumentException(
            "Client not equal to RemoveRandomWithObject's client: client="
                + client
                + " rr="
                + requestGrabber
                + " his object="
                + requestGrabber.getObject());
      addElement(client, requestGrabber);
      if (context != null) {
        clearWakeupTime(context);
      }
    }
  }

  /**
   * Removes and returns a random eligible item from one of the child containers.
   *
   * <p>Behavior by child count:
   *
   * <ul>
   *   <li>0 children → returns {@code null} (empty; caller should prune this node).
   *   <li>1 child → delegates to the only child and propagates emptiness and wakeup semantics.
   *   <li>2 children → tries a randomized child first, then the other; prunes empty children.
   *   <li>≥3 children → attempts a limited randomized scan; on failure falls back to an exhaustive
   *       round that both compacts/prunes and computes the minimum wakeup time.
   * </ul>
   *
   * <p>Fairness: Choice of child is uniformly random among non-excluded children, giving each
   * client an equal chance of progress.
   *
   * <p>Threading: Must be called while holding the root selector lock.
   *
   * @param excluding exclusion list to temporarily skip items and obtain wake times; may be {@code
   *     null}
   * @param context client execution context providing randomness and shared state; must not be
   *     {@code null}
   * @param now current time in milliseconds since the epoch
   * @return a {@link RemoveRandomReturn} containing either an item or a wakeup time, or {@code
   *     null} when this node becomes empty
   */
  @Override
  public RemoveRandomReturn removeRandom(
      RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
    synchronized (root) {
      while (true) {
        if (grabArrays.length == 0) return null;
        if (grabArrays.length == 1) {
          return removeRandomOneOnly(excluding, context, now);
        }
        if (grabArrays.length == 2) {
          RemoveRandomReturn ret = removeRandomTwoOnly(excluding, context, now);
          if (ret == null) continue; // Go around loop again, it has reduced to 1 or 0.
          return ret;
        }
        RandomGrabArrayItem item = removeRandomLimited(excluding, context, now);
        if (item != null) return new RemoveRandomReturn(item);
        else return removeRandomExhaustive(excluding, context, now);
      }
    }
  }

  private RemoveRandomReturn removeRandomExhaustive(
      RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
    synchronized (root) {
      if (grabArrays.length == 0) return null;

      MinWakeup minWakeup = new MinWakeup(Long.MAX_VALUE);
      int x = context.fastWeakRandom.nextInt(grabArrays.length);

      for (int i = 0; i < grabArrays.length; i++) {
        x = nextIndex(x, grabArrays.length);
        RemoveRandomWithObject<T> rga = grabArrays[x];

        if (isExcludedAndRecord(rga, context, now, minWakeup)) {
          continue;
        }

        debugPicked(x, rga);

        RandomGrabArrayItem item = tryPickItem(rga, excluding, context, now, minWakeup);

        debugPickedResult(x, rga, item);

        if (item != null) {
          return new RemoveRandomReturn(item);
        }

        if (rga.isEmpty()) {
          debugRemovingGrabArray(x, rga);
          removeElement(x);
        }
      }

      reduceWakeupTime(minWakeup.value, context);
      return new RemoveRandomReturn(minWakeup.value);
    }
  }

  private int nextIndex(int current, int length) {
    int next = current + 1;
    return (next >= length) ? 0 : next;
  }

  /** Tracks the minimum wakeup time found while iterating child containers. */
  private static final class MinWakeup {
    long value;

    MinWakeup(long initial) {
      this.value = initial;
    }

    void update(long candidate) {
      if (candidate > 0 && value > candidate) {
        value = candidate;
      }
    }
  }

  private boolean isExcludedAndRecord(
      RemoveRandomWithObject<T> rga, ClientContext context, long now, MinWakeup minWakeup) {
    long excludeTime = rga.getWakeupTime(context, now);
    if (excludeTime > 0) {
      minWakeup.update(excludeTime);
      return true;
    }
    return false;
  }

  private RandomGrabArrayItem tryPickItem(
      RemoveRandomWithObject<T> rga,
      RandomGrabArrayItemExclusionList excluding,
      ClientContext context,
      long now,
      MinWakeup minWakeup) {
    RemoveRandomReturn val = rga.removeRandom(excluding, context, now);
    if (val != null) {
      if (val.item != null) return val.item;
      minWakeup.update(val.wakeupTime);
    }
    return null;
  }

  private void debugPicked(int index, RemoveRandomWithObject<T> rga) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Picked {} of {} : {} on {}", index, grabArrays.length, rga, this);
    }
  }

  private void debugPickedResult(
      int index, RemoveRandomWithObject<T> rga, RandomGrabArrayItem item) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "RGA has picked {}/{}: {} rga.isEmpty={}", index, grabArrays.length, item, rga.isEmpty());
    }
  }

  private void debugRemovingGrabArray(int index, RemoveRandomWithObject<T> rga) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Removing grab array {} : {} (is empty)", index, rga);
    }
  }

  private RandomGrabArrayItem removeRandomLimited(
      RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
    synchronized (root) {
      // Count how many child arrays were skipped due to temporary exclusions; bail out after
      // MAX_EXCLUDED to avoid long spins and let the caller decide how to proceed.
      Counter excluded = new Counter();
      while (true) {
        LimitedOutcome outcome = processLimitedIteration(excluding, context, now, excluded);
        if (outcome.item != null) return outcome.item;
        if (outcome.abort) return null;
        // otherwise, continue looping
      }
    }
  }

  private LimitedOutcome processLimitedIteration(
      RandomGrabArrayItemExclusionList excluding,
      ClientContext context,
      long now,
      Counter excluded) {
    if (grabArrays.length == 0) return LimitedOutcome.abortOutcome();

    int x = context.fastWeakRandom.nextInt(grabArrays.length);
    RemoveRandomWithObject<T> rga = grabArrays[x];

    if (rga == null) {
      return handleNullRga(x, excluded) ? LimitedOutcome.abortOutcome() : LimitedOutcome.cont();
    }

    long excludeTime = rga.getWakeupTime(context, now);
    if (excludeTime > 0) {
      return handleExcludedTooMany(excluded)
          ? LimitedOutcome.abortOutcome()
          : LimitedOutcome.cont();
    }

    debugPicked(x, rga);

    RandomGrabArrayItem item = null;
    RemoveRandomReturn val = rga.removeRandom(excluding, context, now);
    if (val != null && val.item != null) item = val.item;

    debugPickedResult(x, rga, item);

    if (item != null) return LimitedOutcome.found(item);

    if (rga.isEmpty()) {
      debugRemovingGrabArray(x, rga);
      removeElement(x);
      return LimitedOutcome.cont();
    }

    return handleExcludedTooMany(excluded) ? LimitedOutcome.abortOutcome() : LimitedOutcome.cont();
  }

  private record LimitedOutcome(RandomGrabArrayItem item, boolean abort) {

    static LimitedOutcome found(RandomGrabArrayItem item) {
      return new LimitedOutcome(item, false);
    }

    static LimitedOutcome cont() {
      return new LimitedOutcome(null, false);
    }

    static LimitedOutcome abortOutcome() {
      return new LimitedOutcome(null, true);
    }
  }

  /** Simple integer holder for counters. */
  private static final class Counter {
    int value;

    boolean incrementAndExceeds() {
      return ++value > MAX_EXCLUDED;
    }
  }

  private boolean handleNullRga(int index, Counter excluded) {
    // Mirror the handling performed in other branches; treat unexpected null as excluded.
    LOG.error("Slot {} is null for client {}", index, grabClients[index]);
    return handleExcludedTooMany(excluded);
  }

  private boolean handleExcludedTooMany(Counter excluded) {
    if (excluded.incrementAndExceeds()) {
      debugTooManyExcluded();
      return true;
    }
    return false;
  }

  private void debugTooManyExcluded() {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Too many sub-arrays are entirely excluded on {} length = {}",
          this,
          grabArrays.length,
          new Exception("error"));
    }
  }

  private RemoveRandomReturn removeRandomTwoOnly(
      RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
    synchronized (root) {
      MinWakeup minWakeup = new MinWakeup(Long.MAX_VALUE);
      // Optimized branch for the common case of two children: choose one at random, then the other.
      int x = context.fastWeakRandom.nextBoolean() ? 1 : 0;
      RemoveRandomWithObject<T> rga = grabArrays[x];
      RemoveRandomWithObject<T> firstRGA = rga;

      if (rga == null) {
        handleInitialNullTwoOnly(x);
        return null;
      }

      debugTwoOnlyStart(rga);

      RandomGrabArrayItem item = null;
      if (!isExcludedAndRecord(rga, context, now, minWakeup)) {
        item = tryPickItem(rga, excluding, context, now, minWakeup);
      }

      if (item != null) {
        debugTwoOnlyReturn(item, rga);
        return new RemoveRandomReturn(item);
      }

      // Try the other one
      x = 1 - x;
      rga = grabArrays[x];
      if (rga == null) {
        return handleSecondNullTwoOnly(x, minWakeup, context);
      }

      if (!isExcludedAndRecord(rga, context, now, minWakeup)) {
        item = tryPickItem(rga, excluding, context, now, minWakeup);
      }

      cleanupTwoOnly(firstRGA, rga, x);

      debugTwoOnlyReturn(item, rga);

      if (item == null) {
        if (grabArrays.length == 0) return null; // Remove this as well
        reduceWakeupTime(minWakeup.value, context);
        return new RemoveRandomReturn(minWakeup.value);
      }
      return new RemoveRandomReturn(item);
    }
  }

  private void handleInitialNullTwoOnly(int index) {
    LOG.error("rga = null on {}", this);
    if (grabArrays[1 - index] == null) {
      LOG.error("other rga is also null on {}", this);
      grabArrays = newGrabberArray(0);
      grabClients = newClientArray(0);
    } else {
      LOG.error("grabArrays[{}] is valid but [{}] is null, correcting...", 1 - index, index);
      grabArrays = asGrabberArray(grabArrays[1 - index]);
      grabClients = asClientArray(grabClients[1 - index]);
    }
  }

  private RemoveRandomReturn handleSecondNullTwoOnly(
      int index, MinWakeup minWakeup, ClientContext context) {
    LOG.error("Other RGA is null later on on {}", this);
    grabArrays = asGrabberArray(grabArrays[1 - index]);
    grabClients = asClientArray(grabClients[1 - index]);
    reduceWakeupTime(minWakeup.value, context);
    return new RemoveRandomReturn(minWakeup.value);
  }

  private void cleanupTwoOnly(
      RemoveRandomWithObject<T> firstRGA, RemoveRandomWithObject<T> secondRGA, int secondIndex) {
    if (firstRGA != null && firstRGA.isEmpty() && secondRGA != null && secondRGA.isEmpty()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Removing both on {} : {} and {} are empty", this, firstRGA, secondRGA);
      grabArrays = newGrabberArray(0);
      grabClients = newClientArray(0);
    } else if (firstRGA != null && firstRGA.isEmpty()) {
      if (LOG.isDebugEnabled()) LOG.debug("Removing first: {} is empty on {}", firstRGA, this);
      // don't use secondRGA reference since it may be nullified logically; use arrays by index
      grabArrays = asGrabberArray(grabArrays[secondIndex]);
      grabClients = asClientArray(grabClients[secondIndex]);
    }
  }

  private void debugTwoOnlyStart(RemoveRandomWithObject<T> rga) {
    if (LOG.isDebugEnabled()) LOG.debug("Only 2, trying {}", rga);
  }

  private void debugTwoOnlyReturn(RandomGrabArrayItem item, RemoveRandomWithObject<T> rga) {
    if (LOG.isDebugEnabled()) LOG.debug("Returning (two items only) {} for {}", item, rga);
  }

  private RemoveRandomReturn removeRandomOneOnly(
      RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
    synchronized (root) {
      // Optimized branch for a single child.
      RemoveRandomWithObject<T> rga = grabArrays[0];
      if (LOG.isDebugEnabled()) LOG.debug("Only one RGA: {}", rga);

      if (rga == null) {
        LOG.error("Only one entry and that is null");
        grabArrays = newGrabberArray(0);
        grabClients = newClientArray(0);
        return null;
      }

      long excludeTime = rga.getWakeupTime(context, now);
      if (excludeTime > 0) return new RemoveRandomReturn(excludeTime);

      MinWakeup minWakeup = new MinWakeup(Long.MAX_VALUE);
      RandomGrabArrayItem item = tryPickItem(rga, excluding, context, now, minWakeup);

      if (rga.isEmpty()) {
        if (LOG.isDebugEnabled()) LOG.debug("Removing only grab array (0) : {}", rga);
        grabArrays = newGrabberArray(0);
        grabClients = newClientArray(0);
      }

      if (LOG.isDebugEnabled()) LOG.debug("Returning (one item only) {} for {}", item, rga);

      if (item == null) {
        if (grabArrays.length == 0) {
          if (LOG.isDebugEnabled()) LOG.debug("Arrays are empty on {}", this);
          return null; // Remove this as well
        }
        reduceWakeupTime(minWakeup.value, context);
        return new RemoveRandomReturn(minWakeup.value);
      }
      return new RemoveRandomReturn(item);
    }
  }

  private void removeElement(int x) {
    synchronized (root) {
      final int grabArraysLength = grabArrays.length;
      int newLen = grabArraysLength > 1 ? grabArraysLength - 1 : 0;
      RemoveRandomWithObject<T>[] newArray = newGrabberArray(newLen);
      if (x > 0) System.arraycopy(grabArrays, 0, newArray, 0, x);
      if (x < grabArraysLength - 1)
        System.arraycopy(grabArrays, x + 1, newArray, x, grabArraysLength - (x + 1));
      grabArrays = newArray;

      T[] newClients = newClientArray(newLen);
      if (x > 0) System.arraycopy(grabClients, 0, newClients, 0, x);
      if (x < grabArraysLength - 1)
        System.arraycopy(grabClients, x + 1, newClients, x, grabArraysLength - (x + 1));
      grabClients = newClients;
    }
  }

  /**
   * Returns whether this node currently holds no child containers.
   *
   * @return {@code true} if empty; otherwise {@code false}
   */
  public boolean isEmpty() {
    synchronized (root) {
      return grabArrays.length == 0;
    }
  }

  /**
   * Returns the number of child containers currently attached to this node.
   *
   * @return non-negative child count
   */
  public int size() {
    synchronized (root) {
      return grabArrays.length;
    }
  }

  /**
   * Removes all references to the given child from this node and prunes this node if it becomes
   * empty.
   *
   * <p>Called by children when they become empty or are being detached. Multiple occurrences are
   * tolerated (and logged at {@code WARN}).
   *
   * @param r the child to remove by identity
   * @param context client context for parent notifications; may be {@code null}
   */
  @Override
  public void maybeRemove(RemoveRandom r, ClientContext context) {
    int count = 0;
    int finalSize;
    synchronized (root) {
      int found;
      while ((found = indexOfGrabArray(r)) != -1) {
        count++;
        if (count > 1) LOG.warn("Found {} many times in {}", r, this);
        removeElement(found);
      }
      finalSize = grabArrays.length;
    }
    // This is not unusual, it was e.g. removed because of being empty.
    // And it has already been removeFrom()'ed.
    if (count == 0 && LOG.isDebugEnabled()) LOG.debug("Not in parent: {} for {}", r, this);
    if (finalSize == 0 && parent != null) {
      parent.maybeRemove(this, context);
    }
  }

  private int indexOfGrabArray(RemoveRandom r) {
    for (int i = 0; i < grabArrays.length; i++) {
      if (grabArrays[i] == r) return i;
    }
    return -1;
  }

  /**
   * Sets the parent used for wakeup propagation and pruning.
   *
   * @param newParent the new parent; may be {@code null}
   */
  @Override
  public void setParent(RemoveRandomParent newParent) {
    synchronized (root) {
      this.parent = newParent;
    }
  }

  /**
   * Returns the parent in the selection tree.
   *
   * @return the parent, or {@code null} if this is a top-level node
   */
  @Override
  public RequestSelectionTreeNode getParentGrabArray() {
    synchronized (root) {
      return parent;
    }
  }

  /**
   * Returns this node's stored wakeup time, normalized to {@code 0} when already past {@code now}.
   *
   * <p>The value reflects the earliest exclusion observed during a previous selection pass and is
   * cleared or reduced when readiness changes.
   *
   * @param context client context (ignored)
   * @param now current time in milliseconds since the epoch
   * @return {@code 0} when ready; otherwise a future timestamp
   */
  @Override
  public long getWakeupTime(ClientContext context, long now) {
    synchronized (root) {
      if (wakeupTime < now) wakeupTime = 0;
      return wakeupTime;
    }
  }

  /**
   * Reduces the stored wakeup time and propagates the reduction up the tree.
   *
   * <p>If this node has no parent (i.e., it is the root of its subtree), it also requests the
   * {@link ClientRequestSelector} to wake up to re-run selection.
   *
   * @param wakeupTime candidate timestamp; only applies if smaller than the current value
   * @param context client context used for parent notifications
   * @return {@code true} if the stored value was reduced, {@code false} otherwise
   */
  @Override
  public boolean reduceWakeupTime(long wakeupTime, ClientContext context) {
    if (LOG.isDebugEnabled())
      LOG.debug("reduceCooldownTime({}) on {}", wakeupTime - System.currentTimeMillis(), this);
    boolean reachedRoot = false;
    synchronized (root) {
      if (this.wakeupTime > wakeupTime) {
        this.wakeupTime = wakeupTime;
        if (parent != null) parent.reduceWakeupTime(wakeupTime, context);
        else reachedRoot = true; // Even if it reduces it we need to wake it up.
      } else return false;
    }
    if (reachedRoot) root.wakeUp(context);
    return true;
  }

  /**
   * Clears the stored wakeup time and requests ancestors to clear theirs as well.
   *
   * @param context client context used for parent notifications
   */
  @Override
  public void clearWakeupTime(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("clearCooldownTime() on {}", this);
    synchronized (root) {
      wakeupTime = 0;
      if (parent != null) parent.clearWakeupTime(context);
    }
  }

  private T[] asClientArray(T client) {
    T[] clients = newClientArray(1);
    clients[0] = client;
    return clients;
  }

  @SuppressWarnings("unchecked")
  private T[] newClientArray(int length) {
    // Safe: we only store values of type T in this array. Generic arrays require an unchecked
    // creation; localize it here.
    return (T[]) new Object[length];
  }

  private RemoveRandomWithObject<T>[] asGrabberArray(RemoveRandomWithObject<T> grabber) {
    RemoveRandomWithObject<T>[] grabbers = newGrabberArray(1);
    grabbers[0] = grabber;
    return grabbers;
  }

  @SuppressWarnings("unchecked")
  private RemoveRandomWithObject<T>[] newGrabberArray(int length) {
    // Safe: array stores RemoveRandomWithObject<T> elements only; creation is centralized here.
    return (RemoveRandomWithObject<T>[]) new RemoveRandomWithObject<?>[length];
  }

  @SuppressWarnings("unchecked")
  private C castGrabber(RemoveRandomWithObject<T> r) {
    // grabArrays holds elements of C which extends RemoveRandomWithObject<T> by construction.
    return (C) r;
  }
}
