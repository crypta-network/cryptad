package network.crypta.node;

import static java.util.concurrent.TimeUnit.HOURS;

import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import network.crypta.io.comm.PeerContext;
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
 *   <li>Requestors — peers that asked us for the key. When the data becomes available, we offer it
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
  WeakReference<PeerContext>[] requestorNodes;

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
  WeakReference<PeerContext>[] requestedNodes;

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

  protected static final WeakReference<PeerContext>[] EMPTY_WEAK_REFERENCE = weakArrayOfSize(0);

  @SuppressWarnings("unchecked")
  private static WeakReference<PeerContext>[] weakArrayOfSize(int size) {
    // Arrays store WeakReference<PeerContext> that should point to PeerNodeUnlocked instances.
    // This localized cast centralizes the unchecked conversion and is safe for our assignments.
    return (WeakReference<PeerContext>[]) new WeakReference<?>[size];
  }

  private static PeerNodeUnlocked asPeerNodeUnlocked(WeakReference<PeerContext> ref) {
    if (ref == null) return null;
    PeerContext ctx = ref.get();
    return ctx instanceof PeerNodeUnlocked peerNodeUnlocked ? peerNodeUnlocked : null;
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
   * @param htl HTL used when the failure occurred; determines the applicability of the timeout.
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
    WeakReference<PeerContext>[] newRequestorNodes =
        weakArrayOfSize(requestorNodes.length + notIncluded - nulls);
    long[] newRequestorTimes = new long[requestorNodes.length + notIncluded - nulls];
    long[] newRequestorBootIDs = new long[requestorNodes.length + notIncluded - nulls];
    short[] newRequestorHTLs = new short[requestorNodes.length + notIncluded - nulls];

    int toIndex = 0;
    int ret = existingIndex;
    for (int i = 0; i < requestorNodes.length; i++) {
      WeakReference<PeerContext> ref = requestorNodes[i];
      PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
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
        PeerNodeUnlocked existing = asPeerNodeUnlocked(requestorNodes[i]);
        if (existing == null) {
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
    boolean includedAlready = false;
    int nulls = 0;
    int ret = -1;
    for (int i = 0; i < requestorNodes.length; i++) {
      PeerNodeUnlocked got = asPeerNodeUnlocked(requestorNodes[i]);
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
    WeakReference<PeerContext>[] newRequestedNodes =
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
      WeakReference<PeerContext> ref = requestedNodes[i];
      PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
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
        PeerNodeUnlocked existing = asPeerNodeUnlocked(requestedNodes[i]);
        if (existing == null) {
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
      PeerNodeUnlocked got = asPeerNodeUnlocked(requestedNodes[i]);
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
   * <p>Intended to be called after the data is stored, and this entry is removed from the failure
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
      WeakReference<PeerContext> ref = requestorNodes[i];
      PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
      boolean valid = pn != null && pn.getBootID() == requestorBootIDs[i];
      if (valid && !set.add(pn)) {
        LOG.error("Node is in requestorNodes twice: {}", pn);
      }
    }
  }

  private void collectRequestedOfferTargets(HashSet<PeerNodeUnlocked> set) {
    for (int i = 0; i < requestedNodes.length; i++) {
      WeakReference<PeerContext> ref = requestedNodes[i];
      PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
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
      WeakReference<PeerContext> ref = requestorNodes[i];
      PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
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
   * Returns whether any valid requestor other than {@code apartFrom} remains within the offer
   * window.
   *
   * <p>Also prunes stale requestors. The {@code now} parameter is used to compare against stored
   * request times.
   *
   * @param apartFrom peer to exclude from consideration; may be {@code null}.
   * @param now current time in milliseconds since epoch.
   * @return {@code true} if at least one other peer wants the key; {@code false} otherwise.
   */
  public synchronized boolean othersWantExcept(PeerNodeUnlocked apartFrom, long now) {
    boolean anyValid = false;
    boolean anyOther = false;
    for (int i = 0; i < requestorNodes.length; i++) {
      WeakReference<PeerContext> ref = requestorNodes[i];
      PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
      if (pn == null) {
        requestorNodes[i] = null;
      } else if (pn.getBootID() != requestorBootIDs[i]) {
        requestorNodes[i] = null;
      } else if (now - requestorTimes[i] < MAX_TIME_BETWEEN_REQUEST_AND_OFFER) {
        anyValid = true;
        if (pn != apartFrom) anyOther = true;
      }
    }
    if (!anyValid) {
      requestorNodes = EMPTY_WEAK_REFERENCE;
      requestorTimes = requestorBootIDs = EMPTY_LONG_ARRAY;
      requestorHTLs = EMPTY_SHORT_ARRAY;
    }
    return anyOther;
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
      WeakReference<PeerContext> ref = requestorNodes[i];
      PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
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
   *
   * @param peer peer to check.
   * @param now current time in milliseconds since epoch.
   * @return {@code true} if we asked this peer recently; {@code false} otherwise.
   */
  public synchronized boolean askedFromPeer(PeerNodeUnlocked peer, long now) {
    boolean anyValid = false;
    boolean ret = false;
    for (int i = 0; i < requestedNodes.length; i++) {
      WeakReference<PeerContext> ref = requestedNodes[i];
      PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
      if (pn == null) {
        requestedNodes[i] = null;
      } else if (pn.getBootID() != requestedBootIDs[i]) {
        requestedNodes[i] = null;
      } else {
        anyValid = true;
        if (now - requestedTimes[i] < MAX_TIME_BETWEEN_REQUEST_AND_OFFER && pn == peer) ret = true;
      }
    }
    if (!anyValid) {
      requestedNodes = EMPTY_WEAK_REFERENCE;
      requestedTimes =
          requestedBootIDs = requestedTimeoutsRF = requestedTimeoutsFT = EMPTY_LONG_ARRAY;
      requestedTimeoutHTLs = EMPTY_SHORT_ARRAY;
    }
    return ret;
  }

  private synchronized boolean isEmptyInternal() {
    if (requestedNodes.length > 0) return false;
    return requestorNodes.length == 0;
  }

  /**
   * Returns the timeout time for the given peer, taking HTL into account.
   *
   * <p>If a timeout was recorded at HTL {@code 1} and we now send at HTL {@code 2}, the timeout is
   * ignored. The result has been an absolute time in milliseconds since epoch, or {@code -1} if
   * there is no applicable timeout.
   *
   * @param peer peer to query.
   * @param htl HTL for the pending request.
   * @param now current time in milliseconds since epoch; used to filter expired timeouts.
   * @param forPerNodeFailureTables when {@code true}, consult per-node failure-table timeouts,
   *     otherwise consult RecentlyFailed timeouts.
   * @return absolute timeout in milliseconds since epoch, or {@code -1} if none.
   */
  @Override
  public synchronized long getTimeoutTime(
      PeerNode peer, short htl, long now, boolean forPerNodeFailureTables) {
    long timeout = -1;
    for (int i = 0; i < requestedNodes.length; i++) {
      if (matchesPeerAndHtl(i, peer, htl)) {
        long thisTimeout = computeTimeout(i, forPerNodeFailureTables);
        if (thisTimeout > now && thisTimeout > timeout) timeout = thisTimeout;
      }
    }
    return timeout;
  }

  private boolean matchesPeerAndHtl(int index, PeerNode peer, short htl) {
    WeakReference<PeerContext> ref = requestedNodes[index];
    PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
    return pn == peer && requestedTimeoutHTLs[index] >= htl;
  }

  private long computeTimeout(int index, boolean forPerNodeFailureTables) {
    return forPerNodeFailureTables ? requestedTimeoutsFT[index] : requestedTimeoutsRF[index];
  }

  /**
   * Compacts both peer lists, removing disconnected, restarted, or expired entries.
   *
   * <p>The method captures the current time internally because a pass over the entire failure table
   * may take a while.
   *
   * @return {@code true} if the entry becomes empty after cleanup; {@code false} otherwise.
   */
  public synchronized boolean cleanup() {
    long now =
        System
            .currentTimeMillis(); // don't pass in as a pass over the whole FT may take a while. get
    // it in the method.

    boolean empty = cleanupRequestor(now);
    empty &= cleanupRequested(now);
    return empty;
  }

  private boolean cleanupRequestor(long now) {
    boolean empty = true;
    int x = 0;
    for (int i = 0; i < requestorNodes.length; i++) {
      WeakReference<PeerContext> ref = requestorNodes[i];
      PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
      boolean valid =
          pn != null
              && pn.getBootID() == requestorBootIDs[i]
              && pn.isConnected()
              && (now - requestorTimes[i] <= MAX_TIME_BETWEEN_REQUEST_AND_OFFER);
      if (valid) {
        empty = false;
        requestorNodes[x] = requestorNodes[i];
        requestorTimes[x] = requestorTimes[i];
        requestorBootIDs[x] = requestorBootIDs[i];
        requestorHTLs[x] = requestorHTLs[i];
        x++;
      }
    }
    if (x < requestorNodes.length) {
      requestorNodes = Arrays.copyOf(requestorNodes, x);
      requestorTimes = Arrays.copyOf(requestorTimes, x);
      requestorBootIDs = Arrays.copyOf(requestorBootIDs, x);
      requestorHTLs = Arrays.copyOf(requestorHTLs, x);
    }

    return empty;
  }

  private boolean cleanupRequested(long now) {
    boolean empty = true;
    int x = 0;
    for (int i = 0; i < requestedNodes.length; i++) {
      WeakReference<PeerContext> ref = requestedNodes[i];
      PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
      boolean valid =
          pn != null
              && pn.getBootID() == requestedBootIDs[i]
              && pn.isConnected()
              && (now - requestedTimes[i] <= MAX_TIME_BETWEEN_REQUEST_AND_OFFER);
      if (valid) {
        empty = false;
        requestedNodes[x] = requestedNodes[i];
        requestedTimes[x] = requestedTimes[i];
        requestedBootIDs[x] = requestedBootIDs[i];
        requestedLocs[x] = requestedLocs[i];
        // Preserve timeouts based on the source slot 'i'. When compacting (x < i), reading from
        // 'x' could observe stale values and drop live per-peer timeouts.
        if (now < requestedTimeoutsRF[i] || now < requestedTimeoutsFT[i]) {
          requestedTimeoutsRF[x] = requestedTimeoutsRF[i];
          requestedTimeoutsFT[x] = requestedTimeoutsFT[i];
          requestedTimeoutHTLs[x] = requestedTimeoutHTLs[i];
        } else {
          requestedTimeoutsRF[x] = -1;
          requestedTimeoutsFT[x] = -1;
          requestedTimeoutHTLs[x] = (short) -1;
        }
        x++;
      }
    }
    if (x < requestedNodes.length) {
      requestedNodes = Arrays.copyOf(requestedNodes, x);
      requestedTimes = Arrays.copyOf(requestedTimes, x);
      requestedBootIDs = Arrays.copyOf(requestedBootIDs, x);
      requestedLocs = Arrays.copyOf(requestedLocs, x);
      requestedTimeoutsRF = Arrays.copyOf(requestedTimeoutsRF, x);
      requestedTimeoutsFT = Arrays.copyOf(requestedTimeoutsFT, x);
      requestedTimeoutHTLs = Arrays.copyOf(requestedTimeoutHTLs, x);
    }
    return empty;
  }

  /** Returns whether both requestor and requested-from lists are empty. */
  public boolean isEmpty() {
    return isEmptyInternal();
  }

  /**
   * Returns the minimum HTL seen among valid requestors, clamped to the provided {@code htl}.
   *
   * <p>Only requestors within {@link #MAX_TIME_BETWEEN_REQUEST_AND_OFFER} are considered. Stale
   * entries are pruned as a side effect.
   *
   * @param htl upper bound to clamp the minimum against.
   * @return the smallest requestor HTL no greater than {@code htl}; if none, returns {@code htl}.
   */
  public synchronized short minRequestorHTL(short htl) {
    long now = System.currentTimeMillis();
    boolean anyValid = false;
    for (int i = 0; i < requestorNodes.length; i++) {
      WeakReference<PeerContext> ref = requestorNodes[i];
      PeerNodeUnlocked pn = asPeerNodeUnlocked(ref);
      if (pn == null) {
        requestorNodes[i] = null;
      } else if (pn.getBootID() != requestorBootIDs[i]) {
        requestorNodes[i] = null;
      } else {
        if ((now - requestorTimes[i] < MAX_TIME_BETWEEN_REQUEST_AND_OFFER)
            && requestorHTLs[i] < htl) htl = requestorHTLs[i];
        anyValid = true;
      }
    }
    if (!anyValid) {
      requestorNodes = EMPTY_WEAK_REFERENCE;
      requestorTimes = requestorBootIDs = EMPTY_LONG_ARRAY;
      requestorHTLs = EMPTY_SHORT_ARRAY;
    }
    return htl;
  }
}
