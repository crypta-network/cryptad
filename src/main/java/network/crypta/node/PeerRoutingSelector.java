package network.crypta.node;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import network.crypta.keys.Key;
import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Selects routing peers based on closeness and peer status.
 *
 * <p>This encapsulates the routing-selection logic formerly embedded in {@link PeerManager}.
 */
public class PeerRoutingSelector {
  private static final Logger LOG = LoggerFactory.getLogger(PeerRoutingSelector.class);

  private final Node node;
  private final PeerRoster roster;
  private final PeerStatusBook statusBook;

  public PeerRoutingSelector(Node node, PeerRoster roster, PeerStatusBook statusBook) {
    this.node = node;
    this.roster = roster;
    this.statusBook = statusBook;
  }

  public PeerNode closerPeer(
      PeerNode pn,
      Set<PeerNode> routedTo,
      double target,
      boolean ignoreSelf,
      boolean calculateMisrouting,
      int minVersion,
      List<Double> addUnpickedLocsTo,
      Key key,
      short outgoingHTL,
      long ignoreBackoffUnder,
      boolean isLocal,
      boolean realTime,
      boolean excludeMandatoryBackoff) {
    return closerPeer(
        pn,
        routedTo,
        target,
        ignoreSelf,
        calculateMisrouting,
        minVersion,
        addUnpickedLocsTo,
        2.0,
        key,
        outgoingHTL,
        ignoreBackoffUnder,
        isLocal,
        realTime,
        null,
        false,
        System.currentTimeMillis(),
        excludeMandatoryBackoff);
  }

  public PeerNode closerPeer(
      PeerNode pn,
      Set<PeerNode> routedTo,
      double target,
      boolean ignoreSelf,
      boolean calculateMisrouting,
      int minVersion,
      List<Double> addUnpickedLocsTo,
      double maxDistance,
      Key key,
      short outgoingHTL,
      long ignoreBackoffUnder,
      boolean isLocal,
      boolean realTime,
      RecentlyFailedReturn recentlyFailed,
      boolean ignoreTimeout,
      long now,
      boolean newLoadManagement) {
    CloserPeerContext ctx = initCloserPeerContext(pn, routedTo, target, ignoreSelf, key);
    evaluateCandidatesInContext(
        ctx,
        pn,
        routedTo,
        minVersion,
        now,
        realTime,
        ignoreTimeout,
        outgoingHTL,
        target,
        maxDistance,
        ignoreSelf,
        addUnpickedLocsTo,
        ignoreBackoffUnder,
        newLoadManagement);

    BestCandidate bestCand = selectBestCandidate(ctx.st, ctx.key);
    if (recentlyFailed != null && LOG.isDebugEnabled()) {
      LOG.debug("Count waiting: {}", ctx.st.countWaiting);
    }

    PeerNode best =
        handleRecentlyFailedIfNeeded(
            bestCand.best,
            bestCand.bestDistance,
            recentlyFailed,
            ctx,
            pn,
            routedTo,
            target,
            ignoreSelf,
            minVersion,
            maxDistance,
            outgoingHTL,
            ignoreBackoffUnder,
            isLocal,
            realTime,
            now,
            newLoadManagement);
    if (best == null) return null;

    reportBackoffPercentIfNeeded(calculateMisrouting);
    postSelectionUpdate(best, calculateMisrouting, addUnpickedLocsTo, ctx.st);
    return best;
  }

  private void reportBackoffPercentIfNeeded(boolean calculateMisrouting) {
    if (!calculateMisrouting) return;
    int connected = statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, false);
    int backedOff =
        statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, false);
    if (backedOff + connected > 0) {
      node.getNodeStats()
          .backedOffPercent
          .report(((double) backedOff) / ((double) backedOff + (double) connected));
    }
  }

  private static final class SelectionRates {
    private final double[] rates;
    private final double total;

    private SelectionRates(double[] rates, double total) {
      this.rates = rates;
      this.total = total;
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

    private CloserPeerContext(
        PeerNode[] peers,
        Key key,
        double myLoc,
        double maxDiff,
        double prevLoc,
        TimedOutNodesList entry,
        SelectionRates selection,
        boolean enableFOAFMitigationHack,
        Set<Double> excludeLocations) {
      this.peers = peers;
      this.key = key;
      this.myLoc = myLoc;
      this.maxDiff = maxDiff;
      this.prevLoc = prevLoc;
      this.entry = entry;
      this.selection = selection;
      this.enableFOAFMitigationHack = enableFOAFMitigationHack;
      this.excludeLocations = excludeLocations;
    }
  }

  private CloserPeerContext initCloserPeerContext(
      PeerNode pn, Set<PeerNode> routedTo, double target, boolean ignoreSelf, Key key) {
    PeerNode[] peers = roster.connectedPeers();
    Key effectiveKey = node.isEnablePerNodeFailureTables() ? key : null;
    if (LOG.isDebugEnabled()) {
      LOG.debug("Choosing closest peer (connectedPeers={}, key={})", peers.length, effectiveKey);
    }

    double myLoc = node.getLocation();
    double maxDiff = ignoreSelf ? Double.MAX_VALUE : Location.distance(myLoc, target);
    double prevLoc = pn != null ? pn.getLocation() : -1.0;
    TimedOutNodesList entry =
        effectiveKey != null ? node.getFailureTable().getTimedOutNodesList(effectiveKey) : null;
    SelectionRates selection = computeSelectionRates(peers);
    boolean enableFOAF = peers.length >= PeerNode.SELECTION_MIN_PEERS && selection.total > 0.0;
    Set<Double> exclude = buildExcludeLocations(myLoc, prevLoc, routedTo);
    return new CloserPeerContext(
        peers, effectiveKey, myLoc, maxDiff, prevLoc, entry, selection, enableFOAF, exclude);
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
      CloserPeerContext ctx,
      PeerNode pn,
      Set<PeerNode> routedTo,
      int minVersion,
      long now,
      boolean realTime,
      boolean ignoreTimeout,
      short outgoingHTL,
      double target,
      double maxDistance,
      boolean ignoreSelf,
      List<Double> addUnpickedLocsTo,
      long ignoreBackoffUnder,
      boolean newLoadManagement) {
    for (int i = 0; i < ctx.peers.length; i++) {
      evaluateCandidate(
          ctx.st,
          ctx.peers[i],
          i,
          pn,
          routedTo,
          minVersion,
          ctx.enableFOAFMitigationHack,
          ctx.selection.rates,
          ctx.selection.total,
          now,
          realTime,
          ctx.entry,
          ignoreTimeout,
          outgoingHTL,
          target,
          ctx.excludeLocations,
          maxDistance,
          ignoreSelf,
          ctx.maxDiff,
          addUnpickedLocsTo,
          ignoreBackoffUnder,
          newLoadManagement);
    }
  }

  private PeerNode handleRecentlyFailedIfNeeded(
      PeerNode best,
      double bestDistance,
      RecentlyFailedReturn recentlyFailed,
      CloserPeerContext ctx,
      PeerNode pn,
      Set<PeerNode> routedTo,
      double target,
      boolean ignoreSelf,
      int minVersion,
      double maxDistance,
      short outgoingHTL,
      long ignoreBackoffUnder,
      boolean isLocal,
      boolean realTime,
      long now,
      boolean newLoadManagement) {
    if (recentlyFailed == null) return best;
    if (ctx.st.countWaiting < maxCountWaiting(ctx.peers)) return best;
    if (!node.isEnableULPRDataPropagation()) return best;
    return maybeHandleRecentlyFailed(
        pn,
        routedTo,
        target,
        ignoreSelf,
        minVersion,
        maxDistance,
        ctx.key,
        outgoingHTL,
        ignoreBackoffUnder,
        isLocal,
        realTime,
        now,
        newLoadManagement,
        ctx.entry,
        ctx.st,
        best,
        bestDistance,
        ctx.myLoc,
        ctx.prevLoc,
        recentlyFailed);
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

  private void evaluateCandidate(
      PeerSelectionState st,
      PeerNode p,
      int index,
      PeerNode origin,
      Set<PeerNode> routedTo,
      int minVersion,
      boolean enableFOAFMitigationHack,
      double[] selectionRates,
      double totalSelectionRate,
      long now,
      boolean realTime,
      TimedOutNodesList entry,
      boolean ignoreTimeout,
      short outgoingHTL,
      double target,
      Set<Double> excludeLocations,
      double maxDistance,
      boolean ignoreSelf,
      double maxDiff,
      List<Double> addUnpickedLocsTo,
      long ignoreBackoffUnder,
      boolean newLoadManagement) {
    if (shouldSkipCandidate(
        p,
        origin,
        routedTo,
        newLoadManagement,
        realTime,
        minVersion,
        enableFOAFMitigationHack,
        selectionRates,
        totalSelectionRate,
        index,
        now)) {
      return;
    }

    TimeoutInfo t = computeTimeoutInfo(st, entry, ignoreTimeout, now, outgoingHTL, p);
    DiffInfo d = computeDiffInfo(p, target, outgoingHTL, excludeLocations);

    if (d.diff > maxDistance) return;
    if (!ignoreSelf && d.diff > maxDiff) {
      if (LOG.isDebugEnabled()) LOG.debug("Ignore; farther than self; maxDiff={}", maxDiff);
      return;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "p.loc={}, target={}, d={} usedD={} timedOut={} for {}",
          d.loc,
          target,
          Location.distance(d.loc, target),
          d.diff,
          t.timedOut,
          p.getPeer());
    }

    boolean chosen =
        updateBestTracking(st, p, d, t.timedOut, t.timeoutFT, ignoreBackoffUnder, realTime);
    if (addUnpickedLocsTo != null && !chosen) {
      double locD = d.loc;
      if (!addUnpickedLocsTo.contains(locD)) addUnpickedLocsTo.add(locD);
    }
  }

  private boolean shouldSkipCandidate(
      PeerNode p,
      PeerNode origin,
      Set<PeerNode> routedTo,
      boolean newLoadManagement,
      boolean realTime,
      int minVersion,
      boolean enableFOAFMitigationHack,
      double[] selectionRates,
      double totalSelectionRate,
      int index,
      long now) {
    boolean skip = false;
    skip = skip || isAlreadyRoutedTo(p, routedTo);
    skip = skip || isOrigin(p, origin);
    skip = skip || isNotRoutable(p);
    skip = skip || isDisconnecting(p);
    skip = skip || lacksLoadStats(p, newLoadManagement, realTime);
    skip = skip || isOldVersion(p, minVersion);
    skip =
        skip
            || isOverSelectedPeer(
                enableFOAFMitigationHack, selectionRates, totalSelectionRate, index, p);
    skip = skip || isInMandatoryBackoff(p, newLoadManagement, realTime, now);
    return skip;
  }

  private boolean isAlreadyRoutedTo(PeerNode p, Set<PeerNode> routedTo) {
    if (routedTo.contains(p)) {
      if (LOG.isDebugEnabled()) LOG.debug("Skipping (already routed to): {}", p.getPeer());
      return true;
    }
    return false;
  }

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

  private TimeoutInfo computeTimeoutInfo(
      PeerSelectionState st,
      TimedOutNodesList entry,
      boolean ignoreTimeout,
      long now,
      short outgoingHTL,
      PeerNode p) {
    long timeoutRF;
    long timeoutFT = -1L;
    if (entry != null && !ignoreTimeout) {
      timeoutFT = entry.getTimeoutTime(p, outgoingHTL, now, true);
      timeoutRF = entry.getTimeoutTime(p, outgoingHTL, now, false);
      if (timeoutRF > now) {
        st.soonestTimeoutWakeup = Math.min(st.soonestTimeoutWakeup, timeoutRF);
        st.countWaiting++;
      }
    }
    boolean timedOut = timeoutFT > now;
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

  private DiffInfo computeDiffInfo(
      PeerNode p, double target, short outgoingHTL, Set<Double> excludeLocations) {
    double loc = p.getLocation();
    boolean direct = true;
    double realDiff = Location.distance(loc, target);
    double diff = realDiff;
    if (p.shallWeRouteAccordingToOurPeersLocation((int) outgoingHTL)) {
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

  private PeerNode maybeHandleRecentlyFailed(
      PeerNode pn,
      Set<PeerNode> routedTo,
      double target,
      boolean ignoreSelf,
      int minVersion,
      double maxDistance,
      Key key,
      short outgoingHTL,
      long ignoreBackoffUnder,
      boolean isLocal,
      boolean realTime,
      long now,
      boolean newLoadManagement,
      TimedOutNodesList entry,
      PeerSelectionState st,
      PeerNode best,
      double bestDistance,
      double myLoc,
      double prevLoc,
      RecentlyFailedReturn recentlyFailed) {
    FirstSecondChoice choice =
        computeFirstSecondChoice(
            pn,
            routedTo,
            target,
            ignoreSelf,
            minVersion,
            maxDistance,
            key,
            outgoingHTL,
            ignoreBackoffUnder,
            isLocal,
            realTime,
            now,
            newLoadManagement,
            entry);
    if (choice == null) return best;
    long until = computeUntil(choice.firstTime, choice.secondTime, st, now);
    long check =
        best == st.closestNotBackedOff
            ? Long.MAX_VALUE
            : checkBackoffsForRecentlyFailed(
                roster.connectedPeers(),
                best,
                target,
                bestDistance,
                myLoc,
                prevLoc,
                now,
                entry,
                outgoingHTL);
    if (check < until) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Reducing RecentlyFailed from {} ms to {} ms due to wake-up check",
            until - now,
            check - now);
      }
      until = check;
    }
    long decidedUntil = decideRecentlyFailedUntil(until, now, key);
    if (decidedUntil >= 0) {
      recentlyFailed.fail(decidedUntil);
      return null;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Not sending RecentlyFailed because will wake up in {}ms", check - now);
    }
    return best;
  }

  private long computeUntil(long firstTime, long secondTime, PeerSelectionState st, long now) {
    long until = Math.min(secondTime, firstTime);
    if (st.countWaiting == maxCountWaiting(roster.connectedPeers())) {
      until = Math.min(until, st.soonestTimeoutWakeup);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Recently failed: {}ms",
            Math.min((long) Integer.MAX_VALUE, st.soonestTimeoutWakeup - now));
      }
    }
    return until;
  }

  private long decideRecentlyFailedUntil(long until, long now, Key key) {
    if (until <= now + MIN_DELTA) return -1L;
    long decidedUntil = until;
    if (decidedUntil > now + FailureTable.RECENTLY_FAILED_TIME) {
      long delay = decidedUntil - now;
      LOG.error("Wake-up time too long: {}", TimeUtil.formatTime(delay));
      decidedUntil = now + FailureTable.RECENTLY_FAILED_TIME;
    }
    return key != null && node.getFailureTable().hadAnyOffers(key) ? -1L : decidedUntil;
  }

  private static final class FirstSecondChoice {
    private final PeerNode first;
    private final long firstTime;
    private final PeerNode second;
    private final long secondTime;

    private FirstSecondChoice(PeerNode first, long firstTime, PeerNode second, long secondTime) {
      this.first = first;
      this.firstTime = firstTime;
      this.second = second;
      this.secondTime = secondTime;
    }
  }

  private FirstSecondChoice computeFirstSecondChoice(
      PeerNode pn,
      Set<PeerNode> routedTo,
      double target,
      boolean ignoreSelf,
      int minVersion,
      double maxDistance,
      Key key,
      short outgoingHTL,
      long ignoreBackoffUnder,
      boolean isLocal,
      boolean realTime,
      long now,
      boolean newLoadManagement,
      TimedOutNodesList entry) {
    if (entry == null) return null;
    PeerNode first =
        closerPeer(
            pn,
            routedTo,
            target,
            ignoreSelf,
            false,
            minVersion,
            null,
            maxDistance,
            key,
            outgoingHTL,
            ignoreBackoffUnder,
            isLocal,
            realTime,
            null,
            true,
            now,
            newLoadManagement);
    if (first == null) return null;
    long firstTime = entry.getTimeoutTime(first, outgoingHTL, now, false);
    if (firstTime <= now) return null;
    if (LOG.isDebugEnabled()) LOG.debug("First choice timeout already passed");

    HashSet<PeerNode> newRoutedTo = new HashSet<>(routedTo);
    newRoutedTo.add(first);
    PeerNode second =
        closerPeer(
            pn,
            newRoutedTo,
            target,
            ignoreSelf,
            false,
            minVersion,
            null,
            maxDistance,
            key,
            outgoingHTL,
            ignoreBackoffUnder,
            isLocal,
            realTime,
            null,
            true,
            now,
            newLoadManagement);
    if (second == null) return null;
    long secondTime = entry.getTimeoutTime(first, outgoingHTL, now, false);
    if (secondTime <= now) return null;
    return new FirstSecondChoice(first, firstTime, second, secondTime);
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
        node.getNodeStats()
            .backedOffPercent
            .report(
                ((double) numberOfRoutingBackedOff)
                    / ((double) numberOfRoutingBackedOff + (double) numberOfConnected));
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
    return clamp(count / 4, 3, 10);
  }

  private int countConnectedPeers(PeerNode[] peers) {
    int count = 0;
    for (PeerNode peer : peers) {
      if (peer.isRoutable()) count++;
    }
    return count;
  }

  private long checkBackoffsForRecentlyFailed(
      PeerNode[] peers,
      PeerNode best,
      double target,
      double bestDistance,
      double myLoc,
      double prevLoc,
      long now,
      TimedOutNodesList entry,
      short outgoingHTL) {
    if (entry == null) return Long.MAX_VALUE;
    long overallWakeup = Long.MAX_VALUE;
    Set<Double> excludeLocations = buildExcludeLocations(myLoc, prevLoc, Set.of());
    for (PeerNode p : peers) {
      long wake =
          wakeupTimeIfBetterAlternative(
              p, best, target, bestDistance, outgoingHTL, excludeLocations, now, entry);
      if (wake == Long.MIN_VALUE) continue;
      if (wake > now && wake < overallWakeup) overallWakeup = wake;
    }
    return overallWakeup;
  }

  private long wakeupTimeIfBetterAlternative(
      PeerNode p,
      PeerNode best,
      double target,
      double bestDistance,
      short outgoingHTL,
      Set<Double> excludeLocations,
      long now,
      TimedOutNodesList entry) {
    if (p == best || !p.isRoutable()) return Long.MIN_VALUE;
    DiffInfo d = computeDiffInfo(p, target, outgoingHTL, excludeLocations);
    if (d.diff >= bestDistance) return Long.MIN_VALUE;
    long wakeup = computeWakeupDeadline(entry, outgoingHTL, now, p);
    if (wakeup <= now) {
      if (LOG.isDebugEnabled())
        LOG.debug("Better node available during RecentlyFailed check: {}", p);
      return Long.MIN_VALUE;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Peer {} exits backoff/timeout in {} ms", p, wakeup - now);
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

  private int clamp(int value, int minValue, int maxValue) {
    if (value < minValue) return minValue;
    return Math.min(value, maxValue);
  }

  private static final long MIN_DELTA = 2000L;
}
