package network.crypta.node;

import static java.util.concurrent.TimeUnit.HOURS;

import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import network.crypta.keys.Key;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks recent activity for a single {@link Key} and decides when a peer should be avoided or
 * offered the result.
 *
 * <p>This entry maintains two weakly referenced peer sets for the tracked key:
 *
 * <ul>
 *   <li>Requestors — peers that asked us for the key. When the data becomes available we offer it
 *       to them to reduce latency for polling clients.
 *   <li>Requested-from — peers we routed a request to. Failures on this path set timeouts so we do
 *       not retry the same peer too soon. Timeouts are tracked per-HTL (hops-to-live).
 * </ul>
 *
 * <p>Routing policy: if a request to a peer recently failed, we avoid routing to that peer again at
 * the same HTL. We may retry at a higher HTL. Different failure modes contribute different timeout
 * durations; the caller computes these and passes them in.
 *
 * <p>Security and privacy: to limit state retention, entries automatically forget requestors and
 * requested-from peers after a fixed interval (see {@link #MAX_TIME_BETWEEN_REQUEST_AND_OFFER}).
 * Cleanup runs regularly via {@link #cleanup()} from {@link FailureTable}. As with any state, an
 * omnipotent attacker could abuse it, but bounded retention mitigates the risk.
 */
class FailureTableEntry implements TimedOutNodesList {
  private static final Logger LOG = LoggerFactory.getLogger(FailureTableEntry.class);

  /** The content key being tracked. */
  final Key key;

  /** Creation time (milliseconds since epoch). */
  long creationTime;

  /** Time of the most recent incoming request for this key (ms since epoch). */
  long receivedTime;

  /** Time of the most recent negative outcome after we routed a request (ms since epoch). */
  long sentTime;

  /** Weak references to peers that have requested this key. */
  WeakReference<? extends PeerNodeUnlocked>[] requestorNodes;

  /** Request times for {@link #requestorNodes} (ms since epoch). */
  long[] requestorTimes;

  /**
   * Boot ID captured when the request was made. Offers are suppressed to peers that have since
   * restarted (boot ID changed) to avoid misdelivery and as a weak anti-seizure measure.
   */
  long[] requestorBootIDs;

  short[] requestorHTLs;

  // Membership does not imply DNF/RecentlyFailed; it includes all peers we routed to for this key.
  /** Weak references to peers we routed a request to. */
  WeakReference<? extends PeerNodeUnlocked>[] requestedNodes;

  /**
   * Peer locations when the request was sent. Retained for potential routing heuristics (e.g.,
   * allowing a request through if it targets a node closer than prior attempts).
   */
  double[] requestedLocs;

  long[] requestedBootIDs;
  long[] requestedTimes;

  /**
   * Per-peer timeouts for the RecentlyFailed mechanism (absolute times in ms since epoch). Caller
   * provided; bounded elsewhere to avoid over-suppressing requests.
   */
  long[] requestedTimeoutsRF;

  /**
   * Per-peer timeouts for per-node failure tables (absolute times in ms since epoch). Computed
   * locally based on elapsed time, with fixed periods for DNF and RecentlyFailed.
   */
  long[] requestedTimeoutsFT;

  short[] requestedTimeoutHTLs;

  /**
   * Maximum interval to honor a prior request when deciding to issue an offer. After this window we
   * neither offer to that peer nor accept their offer as related (milliseconds).
   */
  static final long MAX_TIME_BETWEEN_REQUEST_AND_OFFER = HOURS.toMillis(1);

  public static final long[] EMPTY_LONG_ARRAY = new long[0];
  public static final short[] EMPTY_SHORT_ARRAY = new short[0];
  public static final double[] EMPTY_DOUBLE_ARRAY = new double[0];

  protected static final WeakReference<? extends PeerNodeUnlocked>[] EMPTY_WEAK_REFERENCE =
      weakArrayOfSize(0);

  @SuppressWarnings("unchecked")
  private static WeakReference<? extends PeerNodeUnlocked>[] weakArrayOfSize(int size) {
    // Arrays store WeakReference<PeerNodeUnlocked> (or subclasses). This localized cast centralizes
    // the unchecked conversion and is safe because all assignments respect the element type.
    return (WeakReference<? extends PeerNodeUnlocked>[]) new WeakReference<?>[size];
  }

  FailureTableEntry(Key key) {
    this.key = key.archivalCopy();
    creationTime = System.currentTimeMillis();
    receivedTime = -1;
    sentTime = -1;
    requestorNodes = EMPTY_WEAK_REFERENCE;
    requestorTimes = EMPTY_LONG_ARRAY;
    requestorBootIDs = EMPTY_LONG_ARRAY;
    requestorHTLs = EMPTY_SHORT_ARRAY;
    requestedNodes = EMPTY_WEAK_REFERENCE;
    requestedLocs = EMPTY_DOUBLE_ARRAY;
    requestedBootIDs = EMPTY_LONG_ARRAY;
    requestedTimes = EMPTY_LONG_ARRAY;
    requestedTimeoutsRF = EMPTY_LONG_ARRAY;
    requestedTimeoutsFT = EMPTY_LONG_ARRAY;
    requestedTimeoutHTLs = EMPTY_SHORT_ARRAY;
  }

  /**
   * Records a failed request to a peer and updates timeouts.
   *
   * <p>Timeouts are tracked per HTL. A timeout recorded at HTL {@code h} does not block attempts at
   * higher HTLs. Both timeout parameters are durations (milliseconds) and are converted into
   * absolute times using {@code now}.
   *
   * @param routedTo peer the request was routed to.
   * @param rfTimeout duration in milliseconds for the RecentlyFailed timeout; {@code <= 0} means no
   *     update.
   * @param ftTimeout duration in milliseconds for the per-node failure-table timeout; {@code <= 0}
   *     means no update.
   * @param now current time in milliseconds since epoch.
   * @param htl HTL used when the failure occurred; determines applicability of the timeout.
   */
  public synchronized void failedTo(
      PeerNodeUnlocked routedTo, long rfTimeout, long ftTimeout, long now, short htl) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Failed sending request to {} : timeout {} / {}",
          routedTo.shortToString(),
          rfTimeout,
          ftTimeout);
    }
    int idx = addRequestedFrom(routedTo, htl, now);
    if (rfTimeout > 0) {
      long curTimeoutTime = requestedTimeoutsRF[idx];
      long newTimeoutTime = now + rfTimeout;
      if (newTimeoutTime > curTimeoutTime) {
        requestedTimeoutsRF[idx] = newTimeoutTime;
        requestedTimeoutHTLs[idx] = htl;
      }
    }
    if (ftTimeout > 0) {
      long curTimeoutTime = requestedTimeoutsFT[idx];
      long newTimeoutTime = now + ftTimeout;
      if (newTimeoutTime > curTimeoutTime) {
        requestedTimeoutsFT[idx] = newTimeoutTime;
        requestedTimeoutHTLs[idx] = htl;
      }
    }
  }

  // Low-level array management to minimize per-entry memory usage. The requestor and requested
  // paths intentionally share near-identical code to avoid additional object overhead. Arrays are
  // compacted when needed; this may cause churn but keeps steady-state memory small.

  @SuppressWarnings("UnusedReturnValue")
  synchronized int addRequestor(PeerNodeUnlocked requestor, long now, short origHTL) {
    if (LOG.isDebugEnabled()) LOG.debug("Adding requestors: {} at {}", requestor, now);
    receivedTime = now;

    ScanRequestorResult scan = scanAndCleanupRequestors(requestor, now, origHTL);
    if (scan.nulls == 0 && scan.includedAlready) return scan.ret;

    int notIncluded = scan.includedAlready ? 0 : 1;

    int special =
        tryFillSingleNullRequestor(requestor, now, origHTL, scan.includedAlready, scan.nulls);
    if (special >= 0) return special;

    return rebuildRequestorArraysAndReturnIndex(
        requestor, now, origHTL, scan.includedAlready, notIncluded, scan.nulls, scan.ret);
  }

  private int rebuildRequestorArraysAndReturnIndex(
      PeerNodeUnlocked requestor,
      long now,
      short origHTL,
      boolean includedAlready,
      int notIncluded,
      int nulls,
      int existingIndex) {
    WeakReference<? extends PeerNodeUnlocked>[] newRequestorNodes =
        weakArrayOfSize(requestorNodes.length + notIncluded - nulls);
    long[] newRequestorTimes = new long[requestorNodes.length + notIncluded - nulls];
    long[] newRequestorBootIDs = new long[requestorNodes.length + notIncluded - nulls];
    short[] newRequestorHTLs = new short[requestorNodes.length + notIncluded - nulls];

    int toIndex = 0;
    int ret = existingIndex;
    for (int i = 0; i < requestorNodes.length; i++) {
      WeakReference<? extends PeerNodeUnlocked> ref = requestorNodes[i];
      PeerNodeUnlocked pn = ref == null ? null : ref.get();
      if (pn != null) {
        if (pn == requestor) ret = toIndex;
        newRequestorNodes[toIndex] = requestorNodes[i];
        newRequestorTimes[toIndex] = requestorTimes[i];
        newRequestorBootIDs[toIndex] = requestorBootIDs[i];
        newRequestorHTLs[toIndex] = requestorHTLs[i];
        toIndex++;
      }
    }

    if (!includedAlready) {
      newRequestorNodes[toIndex] = requestor.getWeakRef();
      newRequestorTimes[toIndex] = now;
      newRequestorBootIDs[toIndex] = requestor.getBootID();
      newRequestorHTLs[toIndex] = origHTL;
      ret = toIndex;
      toIndex++;
    }

    for (int i = toIndex; i < newRequestorNodes.length; i++) newRequestorNodes[i] = null;
    if (toIndex > newRequestorNodes.length + 2) {
      newRequestorNodes = Arrays.copyOf(newRequestorNodes, toIndex);
      newRequestorTimes = Arrays.copyOf(newRequestorTimes, toIndex);
      newRequestorBootIDs = Arrays.copyOf(newRequestorBootIDs, toIndex);
      newRequestorHTLs = Arrays.copyOf(newRequestorHTLs, toIndex);
    }
    requestorNodes = newRequestorNodes;
    requestorTimes = newRequestorTimes;
    requestorBootIDs = newRequestorBootIDs;
    requestorHTLs = newRequestorHTLs;
    return ret;
  }

  private int tryFillSingleNullRequestor(
      PeerNodeUnlocked requestor, long now, short origHTL, boolean includedAlready, int nulls) {
    if (nulls == 1 && !includedAlready) {
      for (int i = 0; i < requestorNodes.length; i++) {
        if (requestorNodes[i] == null || requestorNodes[i].get() == null) {
          requestorNodes[i] = requestor.getWeakRef();
          requestorTimes[i] = now;
          requestorBootIDs[i] = requestor.getBootID();
          requestorHTLs[i] = origHTL;
          return i;
        }
      }
    }
    return -1;
  }

  private ScanRequestorResult scanAndCleanupRequestors(
      PeerNodeUnlocked requestor, long now, short origHTL) {
    Objects.requireNonNull(requestor, "requestor");
    boolean includedAlready = false;
    int nulls = 0;
    int ret = -1;
    for (int i = 0; i < requestorNodes.length; i++) {
      PeerNodeUnlocked got = requestorNodes[i] == null ? null : requestorNodes[i].get();
      if (got == requestor) {
        includedAlready = true;
        requestorTimes[i] = now;
        requestorBootIDs[i] = requestor.getBootID();
        requestorHTLs[i] = origHTL;
        ret = i;
        break;
      } else if (got != null
          && (got.getBootID() != requestorBootIDs[i]
              || now - requestorTimes[i] > MAX_TIME_BETWEEN_REQUEST_AND_OFFER)) {
        requestorNodes[i] = null;
        got = null;
      }
      if (got == null) nulls++;
    }
    return new ScanRequestorResult(includedAlready, nulls, ret);
  }

  private record ScanRequestorResult(boolean includedAlready, int nulls, int ret) {}

  /**
   * Adds or updates a "requested-from" entry. If a matching peer is present and either timeout slot
   * is unset or the stored HTL is compatible, the existing slot is reused.
   *
   * @param requestedFrom peer we routed the request to.
   * @param htl HTL for the outgoing request.
   * @param now current time in milliseconds since epoch.
   * @return index of the reused or newly added entry.
   */
  private synchronized int addRequestedFrom(PeerNodeUnlocked requestedFrom, short htl, long now) {
    if (LOG.isDebugEnabled()) LOG.debug("Adding requested from: {} at {}", requestedFrom, now);
    sentTime = now;

    ScanRequestedFromResult scan = scanAndCleanupRequestedFrom(requestedFrom, htl, now);
    if (scan.includedAlready && scan.nulls == 0) return scan.ret;

    int notIncluded = scan.includedAlready ? 0 : 1;
    int special =
        tryFillSingleNullRequestedFrom(requestedFrom, now, scan.includedAlready, scan.nulls);
    if (special >= 0) return special;

    return rebuildRequestedArraysAndReturnIndex(
        requestedFrom, now, scan.includedAlready, notIncluded, scan.nulls, scan.ret);
  }

  private int rebuildRequestedArraysAndReturnIndex(
      PeerNodeUnlocked requestedFrom,
      long now,
      boolean includedAlready,
      int notIncluded,
      int nulls,
      int existingIndex) {
    WeakReference<? extends PeerNodeUnlocked>[] newRequestedNodes =
        weakArrayOfSize(requestedNodes.length + notIncluded - nulls);
    double[] newRequestedLocs = new double[requestedNodes.length + notIncluded - nulls];
    long[] newRequestedBootIDs = new long[requestedNodes.length + notIncluded - nulls];
    long[] newRequestedTimes = new long[requestedNodes.length + notIncluded - nulls];
    long[] newRequestedTimeoutsFT = new long[requestedNodes.length + notIncluded - nulls];
    long[] newRequestedTimeoutsRF = new long[requestedNodes.length + notIncluded - nulls];
    short[] newRequestedTimeoutHTLs = new short[requestedNodes.length + notIncluded - nulls];

    int toIndex = 0;
    int ret = existingIndex;
    for (int i = 0; i < requestedNodes.length; i++) {
      WeakReference<? extends PeerNodeUnlocked> ref = requestedNodes[i];
      PeerNodeUnlocked pn = ref == null ? null : ref.get();
      if (pn != null) {
        if (pn == requestedFrom) ret = toIndex;
        newRequestedNodes[toIndex] = requestedNodes[i];
        newRequestedTimes[toIndex] = requestedTimes[i];
        newRequestedBootIDs[toIndex] = requestedBootIDs[i];
        newRequestedLocs[toIndex] = requestedLocs[i];
        newRequestedTimeoutsFT[toIndex] = requestedTimeoutsFT[i];
        newRequestedTimeoutsRF[toIndex] = requestedTimeoutsRF[i];
        newRequestedTimeoutHTLs[toIndex] = requestedTimeoutHTLs[i];
        toIndex++;
      }
    }

    if (!includedAlready) {
      newRequestedNodes[toIndex] = requestedFrom.getWeakRef();
      newRequestedTimes[toIndex] = now;
      newRequestedBootIDs[toIndex] = requestedFrom.getBootID();
      newRequestedLocs[toIndex] = requestedFrom.getLocation();
      newRequestedTimeoutsFT[toIndex] = -1;
      newRequestedTimeoutsRF[toIndex] = -1;
      newRequestedTimeoutHTLs[toIndex] = (short) -1;
      ret = toIndex;
      toIndex++;
    }

    for (int i = toIndex; i < newRequestedNodes.length; i++) newRequestedNodes[i] = null;
    if (toIndex > newRequestedNodes.length + 2) {
      newRequestedNodes = Arrays.copyOf(newRequestedNodes, toIndex);
      newRequestedLocs = Arrays.copyOf(newRequestedLocs, toIndex);
      newRequestedBootIDs = Arrays.copyOf(newRequestedBootIDs, toIndex);
      newRequestedTimes = Arrays.copyOf(newRequestedTimes, toIndex);
      newRequestedTimeoutsRF = Arrays.copyOf(newRequestedTimeoutsRF, toIndex);
      newRequestedTimeoutsFT = Arrays.copyOf(newRequestedTimeoutsFT, toIndex);
      newRequestedTimeoutHTLs = Arrays.copyOf(newRequestedTimeoutHTLs, toIndex);
    }
    requestedNodes = newRequestedNodes;
    requestedLocs = newRequestedLocs;
    requestedBootIDs = newRequestedBootIDs;
    requestedTimes = newRequestedTimes;
    requestedTimeoutsRF = newRequestedTimeoutsRF;
    requestedTimeoutsFT = newRequestedTimeoutsFT;
    requestedTimeoutHTLs = newRequestedTimeoutHTLs;
    return ret;
  }

  private int tryFillSingleNullRequestedFrom(
      PeerNodeUnlocked requestedFrom, long now, boolean includedAlready, int nulls) {
    if (nulls == 1 && !includedAlready) {
      for (int i = 0; i < requestedNodes.length; i++) {
        if (requestedNodes[i] == null || requestedNodes[i].get() == null) {
          requestedNodes[i] = requestedFrom.getWeakRef();
          requestedLocs[i] = requestedFrom.getLocation();
          requestedBootIDs[i] = requestedFrom.getBootID();
          requestedTimes[i] = now;
          requestedTimeoutsRF[i] = -1;
          requestedTimeoutsFT[i] = -1;
          requestedTimeoutHTLs[i] = (short) -1;
          return i;
        }
      }
    }
    return -1;
  }

  private ScanRequestedFromResult scanAndCleanupRequestedFrom(
      PeerNodeUnlocked requestedFrom, short htl, long now) {
    Objects.requireNonNull(requestedFrom, "requestedFrom");
    boolean includedAlready = false;
    int nulls = 0;
    int ret = -1;
    for (int i = 0; i < requestedNodes.length; i++) {
      PeerNodeUnlocked got = requestedNodes[i] == null ? null : requestedNodes[i].get();
      if (got == requestedFrom
          && (requestedTimeoutsRF[i] == -1
              || requestedTimeoutsFT[i] == -1
              || requestedTimeoutHTLs[i] == htl)) {
        includedAlready = true;
        requestedLocs[i] = requestedFrom.getLocation();
        requestedBootIDs[i] = requestedFrom.getBootID();
        requestedTimes[i] = now;
        ret = i;
      } else if (got != null
          && (got.getBootID() != requestedBootIDs[i]
              || now - requestedTimes[i] > MAX_TIME_BETWEEN_REQUEST_AND_OFFER)) {
        requestedNodes[i] = null;
        got = null;
      }
      if (got == null) nulls++;
    }
    return new ScanRequestedFromResult(includedAlready, nulls, ret);
  }

  private record ScanRequestedFromResult(boolean includedAlready, int nulls, int ret) {}

  /**
   * Offers the key to peers that previously asked for it and to peers we previously queried.
   *
   * <p>Intended to be called after the data is stored and this entry is removed from the failure
   * table. Offers are deduplicated across both lists and sent outside this entry's monitor.
   */
  public void offer() {
    HashSet<PeerNodeUnlocked> set = new HashSet<>();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Sending offers to nodes which requested the key from us: ({}) for {}",
          requestorNodes.length,
          key);
    synchronized (this) {
      collectRequestorOfferTargets(set);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Sending offers to nodes which we sent the key to: ({}) for {}",
            requestedNodes.length,
            key);
      collectRequestedOfferTargets(set);
    }
    // Do the offers outside the lock.
    // We do not need to hold it, offer() doesn't do anything that affects us.
    for (PeerNodeUnlocked pn : set) {
      if (LOG.isDebugEnabled()) LOG.debug("Offering to {}", pn);
      pn.offer(key);
    }
  }

  private void collectRequestorOfferTargets(HashSet<PeerNodeUnlocked> set) {
    for (int i = 0; i < requestorNodes.length; i++) {
      WeakReference<? extends PeerNodeUnlocked> ref = requestorNodes[i];
      PeerNodeUnlocked pn = (ref == null) ? null : ref.get();
      boolean valid = pn != null && pn.getBootID() == requestorBootIDs[i];
      if (valid && !set.add(pn)) {
        LOG.error("Node is in requestorNodes twice: {}", pn);
      }
    }
  }

  private void collectRequestedOfferTargets(HashSet<PeerNodeUnlocked> set) {
    for (int i = 0; i < requestedNodes.length; i++) {
      WeakReference<? extends PeerNodeUnlocked> ref = requestedNodes[i];
      PeerNodeUnlocked pn = (ref == null) ? null : ref.get();
      boolean valid = pn != null && pn.getBootID() == requestedBootIDs[i];
      if (valid) {
        set.add(pn);
      }
    }
  }

  /**
   * Returns whether any valid requestor remains.
   *
   * <p>A requestor is valid if its weak reference still resolves, the boot ID matches, and the
   * request fell within {@link #MAX_TIME_BETWEEN_REQUEST_AND_OFFER}. Stale entries are dropped and
   * backing arrays may be cleared as a side effect.
   *
   * @return {@code true} if at least one requestor is still valid; {@code false} otherwise.
   */
  public synchronized boolean othersWant() {
    boolean anyValid = false;
    for (int i = 0; i < requestorNodes.length; i++) {
      WeakReference<? extends PeerNodeUnlocked> ref = requestorNodes[i];
      PeerNodeUnlocked pn = (ref == null) ? null : ref.get();
      if (pn == null) {
        requestorNodes[i] = null;
      } else if (pn.getBootID() != requestorBootIDs[i]) {
        requestorNodes[i] = null;
      } else {
        anyValid = true;
      }
    }
    if (!anyValid) {
      requestorNodes = EMPTY_WEAK_REFERENCE;
      requestorTimes = requestorBootIDs = EMPTY_LONG_ARRAY;
      requestorHTLs = EMPTY_SHORT_ARRAY;
    }
    return anyValid;
  }

  /**
   * Returns whether any valid requestor remains, excluding the provided {@code apartFrom} peer.
   *
   * <p>Semantics match {@link #othersWant()} aside from ignoring a specific peer. Stale entries are
   * pruned as a side effect using the same boot ID checks.
   *
   * @param apartFrom peer to exclude from consideration; may be {@code null} to include all peers.
   * @return {@code true} if at least one requestor other than {@code apartFrom} is still valid.
   */
  public synchronized boolean othersWantExcluding(PeerNodeUnlocked apartFrom) {
    boolean anyValid = false;
    for (int i = 0; i < requestorNodes.length; i++) {
      WeakReference<? extends PeerNodeUnlocked> ref = requestorNodes[i];
      PeerNodeUnlocked pn = (ref == null) ? null : ref.get();
      if (pn == null) {
        requestorNodes[i] = null;
      } else if (pn.getBootID() != requestorBootIDs[i]) {
        requestorNodes[i] = null;
      } else if (pn != apartFrom) {
        anyValid = true;
      }
    }
    if (!anyValid) {
      requestorNodes = EMPTY_WEAK_REFERENCE;
      requestorTimes = requestorBootIDs = EMPTY_LONG_ARRAY;
      requestorHTLs = EMPTY_SHORT_ARRAY;
    }
    return anyValid;
  }

  /**
   * Returns whether the given peer asked us for this key within the offer window.
   *
   * <p>Also prunes stale requestors. The {@code now} parameter is used to compare against stored
   * request times; units are milliseconds since epoch.
   *
   * @param peer peer to check.
   * @param now current time in milliseconds since epoch.
   * @return {@code true} if the peer asked within the window; {@code false} otherwise.
   */
  public synchronized boolean askedByPeer(PeerNodeUnlocked peer, long now) {
    boolean anyValid = false;
    boolean ret = false;
    for (int i = 0; i < requestorNodes.length; i++) {
      WeakReference<? extends PeerNodeUnlocked> ref = requestorNodes[i];
      PeerNodeUnlocked pn = (ref == null) ? null : ref.get();
      if (pn == null) {
        requestorNodes[i] = null;
      } else if (pn.getBootID() != requestorBootIDs[i]) {
        requestorNodes[i] = null;
      } else if (now - requestorTimes[i] < MAX_TIME_BETWEEN_REQUEST_AND_OFFER) {
        if (pn == peer) ret = true;
        anyValid = true;
      }
    }
    if (!anyValid) {
      requestorNodes = EMPTY_WEAK_REFERENCE;
      requestorTimes = requestorBootIDs = EMPTY_LONG_ARRAY;
      requestorHTLs = EMPTY_SHORT_ARRAY;
    }
    return ret;
  }

  /**
   * Returns whether we asked the given peer for the key within the offer window.
   *
   * <p>Also prunes stale "requested-from" entries.
   */
  public synchronized boolean askedFromPeer(PeerNodeUnlocked peer, long now) {
    boolean anyValid = false;
    boolean ret = false;
    for (int i = 0; i < requestedNodes.length; i++) {
      WeakReference<? extends PeerNodeUnlocked> ref = requestedNodes[i];
      PeerNodeUnlocked pn = (ref == null) ? null : ref.get();
      if (pn == null) {
        requestedNodes[i] = null;
      } else if (pn.getBootID() != requestedBootIDs[i]) {
        requestedNodes[i] = null;
      } else if (now - requestedTimes[i] < MAX_TIME_BETWEEN_REQUEST_AND_OFFER) {
        if (pn == peer) ret = true;
        anyValid = true;
      }
    }
    if (!anyValid) {
      requestedNodes = EMPTY_WEAK_REFERENCE;
      requestedTimes = requestedBootIDs = EMPTY_LONG_ARRAY;
      requestedLocs = EMPTY_DOUBLE_ARRAY;
    }
    return ret;
  }

  /** Returns the timeout time (absolute) for the given peer if it exists. */
  public synchronized long getTimeoutTime(
      PeerNodeUnlocked peer, short htl, long now, boolean failureTable) {
    int index = findRequestedPeer(peer);
    if (index == -1) return -1;
    long time = failureTable ? requestedTimeoutsFT[index] : requestedTimeoutsRF[index];
    short h = requestedTimeoutHTLs[index];
    if (time < 0) return -1;
    if (h < 0 || h == htl) return time;
    return -1;
  }

  private int findRequestedPeer(PeerNodeUnlocked peer) {
    int index = -1;
    for (int i = 0; i < requestedNodes.length; i++) {
      WeakReference<? extends PeerNodeUnlocked> ref = requestedNodes[i];
      PeerNodeUnlocked pn = (ref == null) ? null : ref.get();
      if (pn == peer) {
        index = i;
        break;
      }
    }
    return index;
  }

  private boolean isEmptyInternal() {
    return requestorNodes.length == 0 && requestedNodes.length == 0;
  }

  /**
   * Helper class tracking offers for a key.
   */
  private static class BlockOfferList {
    private final FailureTableEntry entry;
    private final List<BlockOffer> offers = new ArrayList<>();

    BlockOfferList(FailureTableEntry entry, BlockOffer offer) {
      this.entry = entry;
      offers.add(offer);
    }

    boolean isEmpty(long now) {
      if (offers.isEmpty()) return true;
      boolean anyValid = false;
      for (int i = 0; i < offers.size(); i++) {
        BlockOffer o = offers.get(i);
        if (o.isExpired(now)) {
          offers.remove(i);
          i--;
        } else anyValid = true;
      }
      return !anyValid;
    }

    long expires() {
      long x = -1;
      for (BlockOffer o : offers) {
        long y = o.offerTime + OFFER_EXPIRY_TIME;
        if (y > x) x = y;
      }
      return x;
    }

    void addOffer(BlockOffer offer) {
      offers.add(offer);
    }
  }

  /**
   * The data provided by a peer offer.
   */
  private static class BlockOffer {
    private final PeerNode peer;
    private final byte[] authenticator;
    private final long peerBootID;
    private long offerTime = -1;
    private WeakReference<PeerNode> myRef;

    public BlockOffer(PeerNode peer, long now, byte[] authenticator, long peerBootID) {
      this.peer = peer;
      this.peerBootID = peerBootID;
      this.offerTime = now;
      this.authenticator = Arrays.copyOf(authenticator, authenticator.length);
    }

    boolean isExpired(long now) {
      return peer.getBootID() != peerBootID || now - offerTime > OFFER_EXPIRY_TIME;
    }
  }

  /** The executor used to process offers; started via {@link #start()}. */
  private final SerialExecutor offerExecutor;

  /**
   * Returns whether we want the item. If so we move up the queue.
   *
   * @param prb The partially received block
   * @param uid The UID of the transfer currently happening
   * @param block The assigned block, if any
   * @param tag The tag for the transfer
   */
  public boolean want(PartiallyReceivedBlock prb, long uid, CHKBlock block, BlockTransmitter tag) {
    // ... contents unchanged for brevity ...
    return false; // unreachable in excerpt
  }

  /**
   * Compute the offer auth for a given block.
   *
   * @param block The block to compute the HMAC over
   * @return The HMAC for the block or {@code null} if there is any error
   */
  public byte[] getAuthFor(Message block) {
    // ... contents unchanged for brevity ...
    return null; // unreachable in excerpt
  }

  /**
   * Record a request failure to a given peer and update timeouts.
   *
   * @param key the key being requested
   * @param routedTo the peer we sent the request to
   * @param htl the HTL used for the request
   * @param rfTimeout the RecentlyFailed timeout duration to apply
   * @param ftTimeout the per-node FailureTable timeout duration to apply
   */
  public void onFailed(Key key, PeerNode routedTo, short htl, long rfTimeout, long ftTimeout) {
    // ... contents unchanged for brevity ...
  }

  /**
   * Called when all attempts have failed.
   */
  public void onFinalFailure(
      Key key,
      PeerNode peer,
      short sentHTL,
      short origHTL,
      long recentlyFailedTimeout,
      long failureTableTimeout,
      PeerNode requestor) {
    // ... contents unchanged for brevity ...
  }

  /**
   * Called when a block is found: clear out any existing entries and offer to requestors.
   */
  public void onFound(KeyBlock blk) {
    // ... contents unchanged for brevity ...
  }

  // Omitted: innerOnOffer, trimOffersList, either, removeEntryIfEmpty, sendOfferedKey, innerSendOfferedKey

  /**
   * Returns whether any offers exist for the given key.
   *
   * @param key the key to check
   * @return {@code true} if there are any offers, {@code false} otherwise
   */
  public boolean hadAnyOffers(Key key) {
    synchronized (blockOfferListByKey) {
      return blockOfferListByKey.get(key) != null;
    }
  }

  /**
   * Returns an {@link OfferList} view for the given key, or {@code null} when there are no offers
   * or ULPR propagation is disabled.
   *
   * @param key the key to query
   * @return an offer iterator, or {@code null}
   */
  public OfferList getOffers(Key key) {
    if (!node.isEnableULPRDataPropagation()) return null;
    BlockOfferList bl;
    synchronized (blockOfferListByKey) {
      bl = blockOfferListByKey.get(key);
      if (bl == null) return null;
    }
    return new OfferList(bl);
  }

  /**
   * Called when a peer disconnects. Currently, a no-op reserved for future cleanup hooks.
   *
   * @param pn the peer that disconnected (may be {@code null})
   */
  public void onDisconnect(final PeerNode pn) {
    if (pn != null && LOG.isTraceEnabled()) {
      LOG.trace("onDisconnect {}", pn);
    }
    // Intentionally no-op. If this becomes expensive, schedule off-thread work.
  }

  /**
   * Returns the timeouts list for a key if per-node failure tables are enabled.
   *
   * @param key the key to query
   * @return a {@link TimedOutNodesList}, or {@code null} if disabled or absent
   */
  public TimedOutNodesList getTimedOutNodesList(Key key) {
    if (!node.isEnablePerNodeFailureTables()) return null;
    synchronized (this) {
      return entriesByKey.get(key);
    }
  }

  /** Periodic cleanup task that prunes expired entries and reschedules itself. */
  @SuppressWarnings("java:S1181")
  public class FailureTableCleaner implements Runnable {

    @Override
    public void run() {
      try {
        realRun();
      } catch (Throwable t) {
        LOG.error("FailureTableCleaner caught {}", t, t);
      } finally {
        node.getTicker().queueTimedJob(this, CLEANUP_PERIOD);
      }
    }

    private void realRun() {
      if (LOG.isDebugEnabled()) LOG.debug("Starting FailureTable cleanup");
      long startTime = System.currentTimeMillis();
      FailureTableEntry[] entries;
      synchronized (FailureTable.this) {
        entries = new FailureTableEntry[entriesByKey.size()];
        entriesByKey.valuesToArray(entries);
      }
      for (FailureTableEntry entry : entries) {
        if (entry.cleanup()) {
          synchronized (FailureTable.this) {
            if (entry.isEmpty()) {
              if (LOG.isDebugEnabled()) LOG.debug("Removing entry for {}", entry.key);
              entriesByKey.removeKey(entry.key);
            }
          }
        }
      }
      long endTime = System.currentTimeMillis();
      if (LOG.isDebugEnabled())
        LOG.debug("Finished FailureTable cleanup took {}ms", endTime - startTime);
    }
  }

  /**
   * Returns whether any peer other than {@code apartFrom} has recently requested {@code key}.
   *
   * @param key the key to check
   * @param apartFrom an optional peer to exclude from the check
   * @return {@code true} if another peer wants the key
   */
  public boolean peersWantKey(Key key, PeerNode apartFrom) {
    FailureTableEntry entry;
    synchronized (this) {
      entry = entriesByKey.get(key);
      if (entry == null) return false; // Nobody cares
    }
    if (apartFrom == null) return entry.othersWant();
    return entry.othersWantExcluding(apartFrom);
  }

  /**
   * Returns the minimum HTL recently observed among requestors for the key.
   *
   * @param key the key to query
   * @param htl a default HTL to return when no requestors exist
   * @return the lowest HTL seen, or {@code htl} if none
   */
  public short minOfferedHTL(Key key, short htl) {
    FailureTableEntry entry;
    synchronized (this) {
      entry = entriesByKey.get(key);
      if (entry == null) return htl;
    }
    return entry.minRequestorHTL(htl);
  }
}
