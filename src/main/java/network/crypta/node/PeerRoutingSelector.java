package network.crypta.node;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import network.crypta.keys.Key;
import network.crypta.support.TimeUtil;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Selects routing peers based on location closeness and peer status signals.
 *
 * <p>This class centralizes the peer-selection policy that was previously spread across {@link
 * PeerManager}. Callers provide the candidate set and routing context, and the selector evaluates
 * peer distance, routing backoff state, timeouts, and optional recently failed handling to produce
 * the single best peer. The selector does not mutate peer state directly; instead it reports
 * selection statistics and returns the chosen {@link PeerNode} for the caller to route to.
 *
 * <p>Selection is stateful only within a single call and is safe for repeated use as long as
 * callers provide consistent inputs. The implementation assumes that the provided peer roster and
 * status book are kept up to date by the surrounding node lifecycle. Thread safety is delegated to
 * those collaborators; this class itself is immutable after construction.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Filtering peers by eligibility (version, backoff, routing status).
 *   <li>Computing distance and load-based weighting.
 *   <li>Optionally incorporating recently failed retry timing.
 * </ul>
 */
public class PeerRoutingSelector {
  private static final Logger LOG = LoggerFactory.getLogger(PeerRoutingSelector.class);

  private final Node node;
  private final PeerRoster roster;
  private final PeerStatusBook statusBook;

  /**
   * Creates a selector that draws candidates from the provided node services.
   *
   * <p>The selector keeps references to the node, roster, and status book so it can evaluate peer
   * availability, distance, and routing backoff state during selection. The constructor does not
   * validate these collaborators beyond storing them, so callers should ensure they are non-null
   * and fully initialized before invoking selection methods.
   *
   * @param node owning node used for configuration and statistics reporting
   * @param roster source of the currently connected peer set
   * @param statusBook snapshot provider for peer routing status counts
   */
  public PeerRoutingSelector(Node node, PeerRoster roster, PeerStatusBook statusBook) {
    this.node = node;
    this.roster = roster;
    this.statusBook = statusBook;
  }

  /**
   * Selects the closest eligible peer using routing parameters.
   *
   * <p>This method evaluates all connected peers against distance, routing backoff, timeout, and
   * load-management constraints to produce the single best candidate. It can optionally integrate
   * recently failed information to delay retries until an appropriate wake-up time. The selection
   * is deterministic for the given inputs and does not mutate peers; callers remain responsible for
   * updating per-request state and for respecting a {@code null} result.
   *
   * @param params routing selection parameters describing the request and policy
   * @return the selected peer, or {@code null} if none qualifies
   */
  public PeerNode closerPeer(PeerRoutingSelectionParams params) {
    CloserPeerContext ctx = initCloserPeerContext(params);
    evaluateCandidatesInContext(ctx, params);

    BestCandidate bestCand = selectBestCandidate(ctx.st, ctx.key);
    if (params.recentlyFailed() != null && LOG.isDebugEnabled()) {
      LOG.debug("Count waiting: {}", ctx.st.countWaiting);
    }

    PeerNode best = handleRecentlyFailedIfNeeded(bestCand, ctx, params);
    if (best == null) return null;

    reportBackoffPercentIfNeeded(params.calculateMisrouting());
    postSelectionUpdate(best, params.calculateMisrouting(), params.addUnpickedLocsTo(), ctx.st);
    return best;
  }

  private void reportBackoffPercentIfNeeded(boolean calculateMisrouting) {
    if (!calculateMisrouting) return;
    int connected = statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, false);
    int backedOff =
        statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, false);
    if (backedOff + connected > 0) {
      node.network().stats().backedOffPercent.report((double) backedOff / (backedOff + connected));
    }
  }

  private static final class SelectionRates {
    private final double[] rates;
    private final double total;

    private SelectionRates(double[] rates, double total) {
      this.rates = rates;
      this.total = total;
    }

    @Override
    public String toString() {
      return "SelectionRates[total=" + total + ", rates=" + Arrays.toString(rates) + "]";
    }
  }

  @SuppressWarnings("ArrayRecordComponent")
  private record CloserPeerContextData(
      PeerNode[] peers,
      Key key,
      double myLoc,
      double maxDiff,
      double prevLoc,
      TimedOutNodesList entry,
      SelectionRates selection,
      boolean enableFOAFMitigationHack,
      Set<Double> excludeLocations) {
    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj
          instanceof
          CloserPeerContextData(
              PeerNode[] otherPeers,
              Key otherKey,
              double otherMyLoc,
              double otherMaxDiff,
              double otherPrevLoc,
              TimedOutNodesList otherEntry,
              SelectionRates otherSelection,
              boolean otherEnableFOAFMitigationHack,
              Set<Double> otherExcludeLocations))) {
        return false;
      }
      return Arrays.equals(peers, otherPeers)
          && java.util.Objects.equals(key, otherKey)
          && Double.compare(myLoc, otherMyLoc) == 0
          && Double.compare(maxDiff, otherMaxDiff) == 0
          && Double.compare(prevLoc, otherPrevLoc) == 0
          && java.util.Objects.equals(entry, otherEntry)
          && java.util.Objects.equals(selection, otherSelection)
          && enableFOAFMitigationHack == otherEnableFOAFMitigationHack
          && java.util.Objects.equals(excludeLocations, otherExcludeLocations);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(peers);
      result = 31 * result + java.util.Objects.hashCode(key);
      result = 31 * result + Double.hashCode(myLoc);
      result = 31 * result + Double.hashCode(maxDiff);
      result = 31 * result + Double.hashCode(prevLoc);
      result = 31 * result + java.util.Objects.hashCode(entry);
      result = 31 * result + java.util.Objects.hashCode(selection);
      result = 31 * result + Boolean.hashCode(enableFOAFMitigationHack);
      result = 31 * result + java.util.Objects.hashCode(excludeLocations);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "CloserPeerContextData[peers="
          + Arrays.toString(peers)
          + ", key="
          + key
          + ", myLoc="
          + myLoc
          + ", maxDiff="
          + maxDiff
          + ", prevLoc="
          + prevLoc
          + ", entry="
          + entry
          + ", selection="
          + selection
          + ", enableFOAFMitigationHack="
          + enableFOAFMitigationHack
          + ", excludeLocations="
          + excludeLocations
          + "]";
    }
  }

  private static final class CloserPeerContext {
    private final PeerNode[] peers;
    private final Key key;
    private final double myLoc;
    private final double maxDiff;
    private final double prevLoc;
    private final TimedOutNodesList entry;
    private final SelectionRates selection;
    private final boolean enableFOAFMitigationHack;
    private final Set<Double> excludeLocations;
    private final PeerSelectionState st = new PeerSelectionState();

    private CloserPeerContext(CloserPeerContextData data) {
      this.peers = data.peers();
      this.key = data.key();
      this.myLoc = data.myLoc();
      this.maxDiff = data.maxDiff();
      this.prevLoc = data.prevLoc();
      this.entry = data.entry();
      this.selection = data.selection();
      this.enableFOAFMitigationHack = data.enableFOAFMitigationHack();
      this.excludeLocations = data.excludeLocations();
    }
  }

  private static final class CandidateEvaluationContext {
    private final PeerSelectionState st;
    private final PeerNode origin;
    private final Set<PeerNode> routedTo;
    private final int minVersion;
    private final boolean enableFOAFMitigationHack;
    private final double[] selectionRates;
    private final double totalSelectionRate;
    private final TimedOutNodesList entry;
    private final Set<Double> excludeLocations;
    private final double maxDiff;
    private final PeerRoutingSelectionParams params;

    private CandidateEvaluationContext(CloserPeerContext ctx, PeerRoutingSelectionParams params) {
      this.st = ctx.st;
      this.origin = params.origin();
      this.routedTo = params.routedTo();
      this.minVersion = params.minVersion();
      this.enableFOAFMitigationHack = ctx.enableFOAFMitigationHack;
      this.selectionRates = ctx.selection.rates;
      this.totalSelectionRate = ctx.selection.total;
      this.entry = ctx.entry;
      this.excludeLocations = ctx.excludeLocations;
      this.maxDiff = ctx.maxDiff;
      this.params = params;
    }
  }

  private CloserPeerContext initCloserPeerContext(PeerRoutingSelectionParams params) {
    PeerNode[] peers = roster.connectedPeers();
    Key effectiveKey = node.isEnablePerNodeFailureTables() ? params.key() : null;
    if (LOG.isDebugEnabled()) {
      LOG.debug("Choosing closest peer (connectedPeers={}, key={})", peers.length, effectiveKey);
    }

    double myLoc = node.network().location();
    double maxDiff =
        params.ignoreSelf() ? Double.MAX_VALUE : Location.distance(myLoc, params.target());
    double prevLoc = params.origin() != null ? params.origin().getLocation() : -1.0;
    TimedOutNodesList entry =
        effectiveKey != null
            ? node.routing().failureTable().getTimedOutNodesList(effectiveKey)
            : null;
    SelectionRates selection = computeSelectionRates(peers);
    boolean enableFOAF = peers.length >= PeerNode.SELECTION_MIN_PEERS && selection.total > 0.0;
    Set<Double> exclude = buildExcludeLocations(myLoc, prevLoc, params.routedTo());
    CloserPeerContextData data =
        new CloserPeerContextData(
            peers, effectiveKey, myLoc, maxDiff, prevLoc, entry, selection, enableFOAF, exclude);
    return new CloserPeerContext(data);
  }

  private SelectionRates computeSelectionRates(PeerNode[] peers) {
    double[] rates = new double[peers.length];
    double total = 0.0;
    for (int i = 0; i < peers.length; i++) {
      rates[i] = peers[i].selectionRate();
      total += rates[i];
    }
    return new SelectionRates(rates, total);
  }

  private void evaluateCandidatesInContext(
      CloserPeerContext ctx, PeerRoutingSelectionParams params) {
    CandidateEvaluationContext evalContext = new CandidateEvaluationContext(ctx, params);
    for (int i = 0; i < ctx.peers.length; i++) {
      evaluateCandidate(evalContext, ctx.peers[i], i);
    }
  }

  private PeerNode handleRecentlyFailedIfNeeded(
      BestCandidate bestCand, CloserPeerContext ctx, PeerRoutingSelectionParams params) {
    PeerNode best = bestCand.best;
    if (params.recentlyFailed() == null) return best;
    if (ctx.st.countWaiting < maxCountWaiting(ctx.peers)) return best;
    if (!node.isEnableULPRDataPropagation()) return best;
    return maybeHandleRecentlyFailed(
        params, ctx, best, bestCand.bestDistance, params.recentlyFailed());
  }

  private static final class PeerSelectionState {
    private int countWaiting = 0;
    private long soonestTimeoutWakeup = Long.MAX_VALUE;
    private double closestDistance = Double.MAX_VALUE;
    private double closestRealDistance = Double.MAX_VALUE;
    private PeerNode closestBackedOff = null;
    private double closestBackedOffDistance = Double.MAX_VALUE;
    private double closestRealBackedOffDistance = Double.MAX_VALUE;
    private PeerNode closestNotBackedOff = null;
    private double closestNotBackedOffDistance = Double.MAX_VALUE;
    private double closestRealNotBackedOffDistance = Double.MAX_VALUE;
    private PeerNode leastRecentlyTimedOut = null;
    private long timeLeastRecentlyTimedOut = Long.MAX_VALUE;
    private double leastRecentlyTimedOutDistance = Double.MAX_VALUE;
    private PeerNode leastRecentlyTimedOutBackedOff = null;
    private long timeLeastRecentlyTimedOutBackedOff = Long.MAX_VALUE;
    private double leastRecentlyTimedOutBackedOffDistance = Double.MAX_VALUE;
  }

  private static final class BestCandidate {
    private final PeerNode best;
    private final double bestDistance;

    private BestCandidate(PeerNode best, double bestDistance) {
      this.best = best;
      this.bestDistance = bestDistance;
    }
  }

  private Set<Double> buildExcludeLocations(double myLoc, double prevLoc, Set<PeerNode> routedTo) {
    Set<Double> excludeLocations = new HashSet<>();
    excludeLocations.add(myLoc);
    excludeLocations.add(prevLoc);
    for (PeerNode routedToNode : routedTo) {
      excludeLocations.add(routedToNode.getLocation());
    }
    return excludeLocations;
  }

  private void evaluateCandidate(CandidateEvaluationContext ctx, PeerNode p, int index) {
    if (shouldSkipCandidate(ctx, p, index)) {
      return;
    }

    TimeoutInfo t = computeTimeoutInfo(ctx, p);
    DiffInfo d = computeDiffInfo(ctx, p);

    if (d.diff > ctx.params.maxDistance()) return;
    if (!ctx.params.ignoreSelf() && d.diff > ctx.maxDiff) {
      if (LOG.isDebugEnabled()) LOG.debug("Ignore; farther than self; maxDiff={}", ctx.maxDiff);
      return;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "p.loc={}, target={}, d={} usedD={} timedOut={} for {}",
          d.loc,
          ctx.params.target(),
          Location.distance(d.loc, ctx.params.target()),
          d.diff,
          t.timedOut,
          p.getPeer());
    }

    boolean chosen =
        updateBestTracking(
            ctx.st,
            p,
            d,
            t.timedOut,
            t.timeoutFT,
            ctx.params.ignoreBackoffUnder(),
            ctx.params.realTime());
    List<Double> addUnpickedLocsTo = ctx.params.addUnpickedLocsTo();
    if (addUnpickedLocsTo != null && !chosen) {
      double locD = d.loc;
      if (!addUnpickedLocsTo.contains(locD)) addUnpickedLocsTo.add(locD);
    }
  }

  private boolean shouldSkipCandidate(CandidateEvaluationContext ctx, PeerNode p, int index) {
    boolean skip = isAlreadyRoutedTo(p, ctx.routedTo);
    skip = skip || isOrigin(p, ctx.origin);
    skip = skip || isNotRoutable(p);
    skip = skip || isDisconnecting(p);
    skip = skip || lacksLoadStats(p, ctx.params.newLoadManagement(), ctx.params.realTime());
    skip = skip || isOldVersion(p, ctx.minVersion);
    skip =
        skip
            || isOverSelectedPeer(
                ctx.enableFOAFMitigationHack, ctx.selectionRates, ctx.totalSelectionRate, index, p);
    skip =
        skip
            || isInMandatoryBackoff(
                p, ctx.params.newLoadManagement(), ctx.params.realTime(), ctx.params.now());
    return skip;
  }

  private boolean isAlreadyRoutedTo(PeerNode p, Set<PeerNode> routedTo) {
    if (routedTo.contains(p)) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (already routed to): {}", p.getPeer());
      return true;
    }
    return false;
  }

  @SuppressWarnings("ReferenceEquality")
  private boolean isOrigin(PeerNode p, PeerNode origin) {
    if (p == origin) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (req came from): {}", p.getPeer());
      return true;
    }
    return false;
  }

  private boolean isNotRoutable(PeerNode p) {
    if (!p.isRoutable()) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (not connected): {}", p.getPeer());
      return true;
    }
    return false;
  }

  private boolean isDisconnecting(PeerNode p) {
    if (p.isDisconnecting()) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (disconnecting): {}", p.getPeer());
      return true;
    }
    return false;
  }

  private boolean lacksLoadStats(PeerNode p, boolean newLoadManagement, boolean realTime) {
    if (newLoadManagement && p.outputLoadTracker(realTime).getLastIncomingLoadStats() == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (no load stats): {}", p.getPeer());
      return true;
    }
    return false;
  }

  private boolean isOldVersion(PeerNode p, int minVersion) {
    if (minVersion > 0
        && !Version.isBuildAtLeast(
            p.getNodeName(),
            Version.parseBuildNumberFromVersionStr(p.getVersion(), -1),
            minVersion)) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping old version: {}", p.getPeer());
      return true;
    }
    return false;
  }

  private boolean isOverSelectedPeer(
      boolean enableFOAFMitigationHack,
      double[] selectionRates,
      double totalSelectionRate,
      int index,
      PeerNode p) {
    if (enableFOAFMitigationHack) {
      double selectionPercentage = 100.0 * selectionRates[index] / totalSelectionRate;
      if (selectionPercentage > PeerNode.SELECTION_PERCENTAGE_WARNING) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Skipping over-selected peer({}%): {}", selectionPercentage, p.getPeer());
        }
        return true;
      }
    }
    return false;
  }

  private boolean isInMandatoryBackoff(
      PeerNode p, boolean newLoadManagement, boolean realTime, long now) {
    if (newLoadManagement && p.isInMandatoryBackoff(now, realTime)) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (mandatory backoff): {}", p.getPeer());
      return true;
    }
    return false;
  }

  private static final class TimeoutInfo {
    private final boolean timedOut;
    private final long timeoutFT;

    private TimeoutInfo(boolean timedOut, long timeoutFT) {
      this.timedOut = timedOut;
      this.timeoutFT = timeoutFT;
    }
  }

  private TimeoutInfo computeTimeoutInfo(CandidateEvaluationContext ctx, PeerNode p) {
    long timeoutRF;
    long timeoutFT = -1L;
    if (ctx.entry != null && !ctx.params.ignoreTimeout()) {
      timeoutFT = ctx.entry.getTimeoutTime(p, ctx.params.outgoingHTL(), ctx.params.now(), true);
      timeoutRF = ctx.entry.getTimeoutTime(p, ctx.params.outgoingHTL(), ctx.params.now(), false);
      if (timeoutRF > ctx.params.now()) {
        ctx.st.soonestTimeoutWakeup = Math.min(ctx.st.soonestTimeoutWakeup, timeoutRF);
        ctx.st.countWaiting++;
      }
    }
    boolean timedOut = timeoutFT > ctx.params.now();
    return new TimeoutInfo(timedOut, timeoutFT);
  }

  private static final class DiffInfo {
    private final double loc;
    private final double diff;
    private final double realDiff;
    private final boolean direct;

    private DiffInfo(double loc, double diff, double realDiff, boolean direct) {
      this.loc = loc;
      this.diff = diff;
      this.realDiff = realDiff;
      this.direct = direct;
    }
  }

  private DiffInfo computeDiffInfo(CandidateEvaluationContext ctx, PeerNode p) {
    return computeDiffInfo(p, ctx.params.target(), ctx.params.outgoingHTL(), ctx.excludeLocations);
  }

  private DiffInfo computeDiffInfo(
      PeerNode p, double target, short outgoingHTL, Set<Double> excludeLocations) {
    double loc = p.getLocation();
    boolean direct = true;
    double realDiff = Location.distance(loc, target);
    double diff = realDiff;
    if (p.shallWeRouteAccordingToOurPeersLocation(outgoingHTL)) {
      double l = p.getClosestPeerLocation(target, excludeLocations);
      if (!Double.isNaN(l)) {
        double newDiff = Location.distance(l, target);
        if (newDiff < diff) {
          loc = l;
          diff = newDiff;
          direct = false;
        }
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug("Peer {} publishes peer locations; closest candidate distance={}", p, diff);
      }
    }
    return new DiffInfo(loc, diff, realDiff, direct);
  }

  private boolean updateBestTracking(
      PeerSelectionState st,
      PeerNode p,
      DiffInfo d,
      boolean timedOut,
      long timeoutFT,
      long ignoreBackoffUnder,
      boolean realTime) {
    boolean chosen = updateOverallBest(st, p, d);
    boolean backedOff = p.isRoutingBackedOff(ignoreBackoffUnder, realTime);
    chosen = chosen || updateBestBackedOff(st, p, d, timedOut, backedOff);
    chosen = chosen || updateBestNotBackedOff(st, p, d, timedOut, backedOff);
    updateTimedOutOrdering(st, p, d.diff, timeoutFT, timedOut, backedOff);
    return chosen;
  }

  private boolean updateOverallBest(PeerSelectionState st, PeerNode p, DiffInfo d) {
    if (d.diff < st.closestDistance
        || (Math.abs(d.diff - st.closestDistance) < Double.MIN_VALUE * 2
            && (d.direct || d.realDiff < st.closestRealDistance))) {
      st.closestDistance = d.diff;
      st.closestRealDistance = d.realDiff;
      if (LOG.isDebugEnabled()) {
        LOG.debug("New best distance={} at {} for {}", d.diff, d.loc, p.getPeer());
      }
      return true;
    }
    return false;
  }

  private boolean updateBestBackedOff(
      PeerSelectionState st, PeerNode p, DiffInfo d, boolean timedOut, boolean backedOff) {
    if (backedOff
        && (d.diff < st.closestBackedOffDistance
            || (Math.abs(d.diff - st.closestBackedOffDistance) < Double.MIN_VALUE * 2
                && (d.direct || d.realDiff < st.closestRealBackedOffDistance)))
        && !timedOut) {
      st.closestBackedOffDistance = d.diff;
      st.closestBackedOff = p;
      st.closestRealBackedOffDistance = d.realDiff;
      if (LOG.isDebugEnabled()) {
        LOG.debug("New best-backed-off distance={} at {} for {}", d.diff, d.loc, p.getPeer());
      }
      return true;
    }
    return false;
  }

  private boolean updateBestNotBackedOff(
      PeerSelectionState st, PeerNode p, DiffInfo d, boolean timedOut, boolean backedOff) {
    if (!backedOff
        && (d.diff < st.closestNotBackedOffDistance
            || (Math.abs(d.diff - st.closestNotBackedOffDistance) < Double.MIN_VALUE * 2
                && (d.direct || d.realDiff < st.closestRealNotBackedOffDistance)))
        && !timedOut) {
      st.closestNotBackedOffDistance = d.diff;
      st.closestNotBackedOff = p;
      st.closestRealNotBackedOffDistance = d.realDiff;
      if (LOG.isDebugEnabled()) {
        LOG.debug("New best-not-backed-off distance={} at {} for {}", d.diff, d.loc, p.getPeer());
      }
      return true;
    }
    return false;
  }

  private void updateTimedOutOrdering(
      PeerSelectionState st,
      PeerNode p,
      double diff,
      long timeoutFT,
      boolean timedOut,
      boolean backedOff) {
    if (!timedOut) return;
    if (!backedOff) {
      if (timeoutFT < st.timeLeastRecentlyTimedOut) {
        st.timeLeastRecentlyTimedOut = timeoutFT;
        st.leastRecentlyTimedOut = p;
        st.leastRecentlyTimedOutDistance = diff;
      }
    } else if (timeoutFT < st.timeLeastRecentlyTimedOutBackedOff) {
      st.timeLeastRecentlyTimedOutBackedOff = timeoutFT;
      st.leastRecentlyTimedOutBackedOff = p;
      st.leastRecentlyTimedOutBackedOffDistance = diff;
    }
  }

  private BestCandidate selectBestCandidate(PeerSelectionState st, Key key) {
    PeerNode best = st.closestNotBackedOff;
    double bestDistance = st.closestNotBackedOffDistance;
    if (best == null) {
      if (st.leastRecentlyTimedOut != null) {
        best = st.leastRecentlyTimedOut;
        bestDistance = st.leastRecentlyTimedOutDistance;
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Using least recently failed in-timeout-period peer for key: {} for {}",
              best.shortToString(),
              key);
        }
      } else if (st.closestBackedOff != null) {
        best = st.closestBackedOff;
        bestDistance = st.closestBackedOffDistance;
        if (LOG.isDebugEnabled()) {
          LOG.debug("Using best backed-off peer for key: {}", best.shortToString());
        }
      } else if (st.leastRecentlyTimedOutBackedOff != null) {
        best = st.leastRecentlyTimedOutBackedOff;
        bestDistance = st.leastRecentlyTimedOutBackedOffDistance;
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Using least recently failed in-timeout-period backed-off peer for key: {} for {}",
              best.shortToString(),
              key);
        }
      }
    }
    return new BestCandidate(best, bestDistance);
  }

  @SuppressWarnings("ReferenceEquality")
  private PeerNode maybeHandleRecentlyFailed(
      PeerRoutingSelectionParams params,
      CloserPeerContext ctx,
      PeerNode best,
      double bestDistance,
      RecentlyFailedReturn recentlyFailed) {
    FirstSecondChoice choice = computeFirstSecondChoice(params, ctx.entry);
    if (choice == null) return best;
    long until = computeUntil(choice.firstTime, choice.secondTime, ctx.st, params.now());
    long check =
        best == ctx.st.closestNotBackedOff
            ? Long.MAX_VALUE
            : checkBackoffsForRecentlyFailed(ctx, best, bestDistance, params);
    if (check < until) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Reducing RecentlyFailed from {} ms to {} ms due to wake-up check",
            until - params.now(),
            check - params.now());
      }
      until = check;
    }
    long decidedUntil = decideRecentlyFailedUntil(until, params.now(), ctx.key);
    if (decidedUntil >= 0) {
      recentlyFailed.fail(decidedUntil);
      return null;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Not sending RecentlyFailed because will wake up in {}ms", check - params.now());
    }
    return best;
  }

  private long computeUntil(long firstTime, long secondTime, PeerSelectionState st, long now) {
    long until = Math.min(secondTime, firstTime);
    if (st.countWaiting == maxCountWaiting(roster.connectedPeers())) {
      until = Math.min(until, st.soonestTimeoutWakeup);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Recently failed: {}ms", Math.min(Integer.MAX_VALUE, st.soonestTimeoutWakeup - now));
      }
    }
    return until;
  }

  private long decideRecentlyFailedUntil(long until, long now, Key key) {
    if (until <= now + MIN_DELTA) return -1L;
    long decidedUntil = until;
    if (decidedUntil > now + FailureTable.RECENTLY_FAILED_TIME) {
      long delay = decidedUntil - now;
      if (LOG.isErrorEnabled()) {
        LOG.error("Wake-up time too long: {}", TimeUtil.formatTime(delay));
      }
      decidedUntil = now + FailureTable.RECENTLY_FAILED_TIME;
    }
    return key != null && node.routing().failureTable().hadAnyOffers(key) ? -1L : decidedUntil;
  }

  private static final class FirstSecondChoice {
    private final long firstTime;
    private final long secondTime;

    private FirstSecondChoice(long firstTime, long secondTime) {
      this.firstTime = firstTime;
      this.secondTime = secondTime;
    }
  }

  private FirstSecondChoice computeFirstSecondChoice(
      PeerRoutingSelectionParams params, TimedOutNodesList entry) {
    if (entry == null) return null;
    PeerNode first = closerPeer(buildRetryParams(params, params.routedTo()));
    if (first == null) return null;
    long firstTime = entry.getTimeoutTime(first, params.outgoingHTL(), params.now(), false);
    if (firstTime <= params.now()) return null;
    if (LOG.isDebugEnabled()) LOG.debug("First choice timeout already passed");

    HashSet<PeerNode> newRoutedTo = new HashSet<>(params.routedTo());
    newRoutedTo.add(first);
    PeerNode second = closerPeer(buildRetryParams(params, newRoutedTo));
    if (second == null) return null;
    long secondTime = entry.getTimeoutTime(second, params.outgoingHTL(), params.now(), false);
    if (secondTime <= params.now()) return null;
    return new FirstSecondChoice(firstTime, secondTime);
  }

  private PeerRoutingSelectionParams buildRetryParams(
      PeerRoutingSelectionParams params, Set<PeerNode> routedTo) {
    return new PeerRoutingSelectionParams(
        params.origin(),
        routedTo,
        params.target(),
        params.ignoreSelf(),
        false,
        params.minVersion(),
        null,
        params.maxDistance(),
        params.key(),
        params.outgoingHTL(),
        params.ignoreBackoffUnder(),
        params.isLocal(),
        params.realTime(),
        null,
        true,
        params.now(),
        params.newLoadManagement());
  }

  private void postSelectionUpdate(
      PeerNode best,
      boolean calculateMisrouting,
      List<Double> addUnpickedLocsTo,
      PeerSelectionState st) {
    if (best == null) return;
    if (calculateMisrouting) {
      int numberOfConnected =
          statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, false);
      int numberOfRoutingBackedOff =
          statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, false);
      if (numberOfRoutingBackedOff + numberOfConnected > 0) {
        node.network()
            .stats()
            .backedOffPercent
            .report(
                (double) numberOfRoutingBackedOff / (numberOfRoutingBackedOff + numberOfConnected));
      }
    }
    if (addUnpickedLocsTo != null
        && st.closestNotBackedOff != null
        && st.closestBackedOff != null) {
      addUnpickedLocsTo.add(st.closestBackedOff.getLocation());
    }
  }

  private int maxCountWaiting(PeerNode[] peers) {
    int count = countConnectedPeers(peers);
    return clampCountWaiting(count / 4);
  }

  private int countConnectedPeers(PeerNode[] peers) {
    int count = 0;
    for (PeerNode peer : peers) {
      if (peer.isRoutable()) count++;
    }
    return count;
  }

  private long checkBackoffsForRecentlyFailed(
      CloserPeerContext ctx,
      PeerNode best,
      double bestDistance,
      PeerRoutingSelectionParams params) {
    if (ctx.entry == null) return Long.MAX_VALUE;
    long overallWakeup = Long.MAX_VALUE;
    Set<Double> excludeLocations = buildExcludeLocations(ctx.myLoc, ctx.prevLoc, Set.of());
    for (PeerNode p : ctx.peers) {
      long wake =
          wakeupTimeIfBetterAlternative(p, best, bestDistance, params, excludeLocations, ctx.entry);
      if (wake == Long.MIN_VALUE) continue;
      if (wake > params.now() && wake < overallWakeup) overallWakeup = wake;
    }
    return overallWakeup;
  }

  @SuppressWarnings("ReferenceEquality")
  private long wakeupTimeIfBetterAlternative(
      PeerNode p,
      PeerNode best,
      double bestDistance,
      PeerRoutingSelectionParams params,
      Set<Double> excludeLocations,
      TimedOutNodesList entry) {
    if (p == best || !p.isRoutable()) return Long.MIN_VALUE;
    DiffInfo d = computeDiffInfo(p, params.target(), params.outgoingHTL(), excludeLocations);
    if (d.diff >= bestDistance) return Long.MIN_VALUE;
    long wakeup = computeWakeupDeadline(entry, params.outgoingHTL(), params.now(), p);
    if (wakeup <= params.now()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Better node available during RecentlyFailed check: {}", p);
      return Long.MIN_VALUE;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Peer {} exits backoff/timeout in {} ms", p, wakeup - params.now());
    }
    return wakeup;
  }

  private long computeWakeupDeadline(
      TimedOutNodesList entry, short outgoingHTL, long now, PeerNode p) {
    long wakeup = 0L;
    long timeoutFT = entry.getTimeoutTime(p, outgoingHTL, now, true);
    long timeoutRF = entry.getTimeoutTime(p, outgoingHTL, now, false);
    if (timeoutFT > now) wakeup = Math.max(wakeup, timeoutFT);
    if (timeoutRF > now) wakeup = Math.max(wakeup, timeoutRF);
    long bulkBackoff = p.routingBackedOffUntilBulk;
    long rtBackoff = p.routingBackedOffUntilRT;
    long candidate = Long.MAX_VALUE;
    if (bulkBackoff > now) candidate = bulkBackoff;
    if (rtBackoff > now && rtBackoff < candidate) candidate = rtBackoff;
    if (candidate != Long.MAX_VALUE) wakeup = Math.max(wakeup, candidate);
    return wakeup;
  }

  private int clampCountWaiting(int value) {
    if (value < MIN_COUNT_WAITING) return MIN_COUNT_WAITING;
    return Math.min(value, MAX_COUNT_WAITING);
  }

  private static final long MIN_DELTA = 2000L;
  private static final int MIN_COUNT_WAITING = 3;
  private static final int MAX_COUNT_WAITING = 10;
}
