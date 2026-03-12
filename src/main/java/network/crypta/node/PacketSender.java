package network.crypta.node;

import java.util.ArrayList;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.TimeUtil;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.NANOSECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Sends outgoing packets for peers on a dedicated high‑priority thread.
 *
 * <p>Responsibilities: - Drain per‑peer queues and decide what to send next (full packets, acks,
 * handshakes). - Minimize latency by prioritizing overdue items while respecting output throttling.
 * - Coordinate with the {@link PeerManager} and the node ticker for periodic maintenance.
 *
 * <p>Threading and lifecycle: - Runs on a daemon {@link Thread} created via {@link NativeThread}. -
 * The main loop is resilient: it logs and continues on unexpected {@link Throwable}s. - Wake‑ups
 * use {@link #wakeUp()} which {@code notifyAll()}s on this instance.
 *
 * <p>Timing and units: - Time values are in milliseconds unless otherwise noted. - {@link
 * #MAX_COALESCING_DELAY} bounds per‑message coalescing for realtime traffic; bulk coalescing uses
 * {@link #MAX_COALESCING_DELAY_BULK}.
 *
 * <p>Inputs/outputs: - Reads peer state via {@link PeerNode} accessors; writes by invoking
 * send/handshake methods. - Emits structured logs for diagnostics; does not expose public
 * callbacks.
 */
// Historical note: This component once doubled as an ad‑hoc scheduler. Today recurring work is
// delegated to the Ticker; PacketSender focuses on sending decisions and timing.
public class PacketSender implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(PacketSender.class);

  /** Maximum time to queue a message before sending (milliseconds). */
  static final long MAX_COALESCING_DELAY = 100L;

  /**
   * Maximum time to queue bulk data before sending (milliseconds).
   *
   * <p>Bulk payloads typically fill a packet and are sent immediately; this value still influences
   * realtime vs. bulk selection (see {@code PeerMessageQueue.addMessages()}).
   */
  static final long MAX_COALESCING_DELAY_BULK = SECONDS.toMillis(5);

  // Unused legacy thresholds for opennet connect timing were removed.

  final NativeThread myThread;
  final Node node;
  NodeStats stats;
  volatile long lastReportedNoPackets;
  final AtomicLong lastReceivedPacketFromAnyNode = new AtomicLong();
  private final Random localRandom;
  private volatile boolean stopping;
  private boolean wakeUpRequested;

  public PacketSender(Node node) {
    this.node = node;
    myThread =
        new NativeThread(
            this,
            "PacketSender thread for " + node.network().darknetPortNumber(),
            NativeThread.PriorityLevel.MAX_PRIORITY.value,
            false);
    myThread.setDaemon(true);
    localRandom = node.bootstrap().createRandom();
  }

  /**
   * Starts the packet sender thread using the provided stats counters.
   *
   * @param stats node statistics collector for bandwidth accounting
   */
  public void start(NodeStats stats) {
    this.stats = stats;
    LOG.info("Start PacketSender");
    myThread.start();
  }

  /**
   * Requests the packet sender thread to stop and wake up promptly.
   *
   * <p>This is a best-effort signal used during shutdown. It is safe to call multiple times.
   */
  public void stop() {
    if (stopping) return;
    stopping = true;
    wakeUp();
  }

  private void schedulePeriodicJob() {

    node.network()
        .ticker()
        .queueTimedJob(
            new Runnable() {

              @Override
              public void run() {
                if (stopping) return;
                try {
                  long now = System.currentTimeMillis();
                  if (LOG.isDebugEnabled()) LOG.debug("Start schedulePeriodicJob at {}", now);
                  PeerManager pm = node.network().peers();
                  pm.maybeLogPeerNodeStatusSummary(now);
                  pm.maybeUpdateOldestNeverConnectedDarknetPeerAge(now);
                  stats.maybeUpdatePeerManagerUserAlertStats(now);
                  stats.maybeUpdateNodeIOStats(now);
                  pm.maybeUpdatePeerNodeRoutableConnectionStats(now);

                  if (LOG.isDebugEnabled())
                    LOG.debug("Complete schedulePeriodicJob at {}", System.currentTimeMillis());
                } finally {
                  if (!stopping) {
                    node.network().ticker().queueTimedJob(this, 1000);
                  }
                }
              }
            },
            1000);
  }

  /**
   * Runs the main sending loop.
   *
   * <p>Behavior: - Schedules periodic maintenance via the node ticker. - Iterates indefinitely,
   * selecting and sending work for peers, then sleeping until the next action time. - Logs and
   * continues on unexpected {@link Throwable}s so the thread remains alive.
   */
  @Override
  @SuppressWarnings({"java:S2189", "java:S1181"})
  public void run() {
    if (LOG.isDebugEnabled()) LOG.debug("In PacketSender.run()");

    if (stopping) return;
    schedulePeriodicJob();
    // Process peers perform the selected action, then sleep until the next action time.
    while (!stopping) {
      lastReceivedPacketFromAnyNode.set(lastReportedNoPackets);
      try {
        realRun();
      } catch (Throwable t) {
        LOG.error("Unhandled throwable in PacketSender: {}", t, t);
      }
    }
  }

  /**
   * Send loop. Strategy: - Each peer can tell us when its data needs to be sent by. This is usually
   * 100ms after it is posted. It could vary by message type. Acknowledgements also become valid
   * 100ms after being queued. - If any peer's data is overdue, send the data from the most overdue
   * peer. - If there are peers with more than a packet's worth of data queued, send the data from
   * the peer with the oldest data. - If there are peers with overdue ack's, send to the peer whose
   * acks are oldest.
   *
   * <p>It does not attempt to ensure fairness, it attempts to minimize latency. Fairness is best
   * dealt with at a higher level e.g., requests, although some transfers are not part of requests,
   * e.g., bulk f2f transfers, so we may need to reconsider this eventually...
   */
  private void realRun() {
    long now = System.currentTimeMillis();
    PeerManager pm = node.network().peers();
    PeerNode[] nodes = pm.myPeers();

    RunState state = initRunState(now);

    PeerAggregation agg = new PeerAggregation();
    agg.nextActionTime = state.nextActionTime;
    agg.oldTempNow = now;

    for (PeerNode pn : nodes) {
      now = System.currentTimeMillis();
      processPeer(pn, now, state.canSendThrottled, agg);
    }

    Selection sel = selectNextAction(now, agg);
    performSelection(now, sel, agg);

    updateNextActionFromAggregates(agg);

    processOldOpennetPeers(now);

    sleepUntilNextAction(now, agg.nextActionTime);
  }

  private record RunState(boolean canSendThrottled, long nextActionTime) {}

  private RunState initRunState(long now) {
    long nextActionTime = Long.MAX_VALUE;
    boolean canSendThrottled;

    int maxPacketSize = node.network().darknetCrypto().getSocket().getMaxPacketSize();
    long count = node.network().outputThrottle().getCount();
    if (count > maxPacketSize) {
      canSendThrottled = true;
    } else {
      long canSendAt = node.network().outputThrottle().getNanosPerTick() * (maxPacketSize - count);
      canSendAt = MILLISECONDS.convert(canSendAt + MILLISECONDS.toNanos(1) - 1, NANOSECONDS);
      if (LOG.isDebugEnabled()) LOG.debug("Can send throttled packets in {} ms", canSendAt);
      nextActionTime = Math.min(nextActionTime, now + canSendAt);
      canSendThrottled = false;
    }

    return new RunState(canSendThrottled, nextActionTime);
  }

  private static final class PeerAggregation {
    long lowestUrgentSendTime = Long.MAX_VALUE;
    ArrayList<PeerNode> urgentSendPeers = null;

    long lowestFullPacketSendTime = Long.MAX_VALUE;
    ArrayList<PeerNode> urgentFullPacketPeers = null;

    long lowestAckTime = Long.MAX_VALUE;
    ArrayList<PeerNode> ackPeers = null;

    long lowestHandshakeTime = Long.MAX_VALUE;
    ArrayList<PeerNode> handshakePeers = null;

    long nextActionTime = Long.MAX_VALUE;
    long oldTempNow;
  }

  private void processPeer(PeerNode pn, long now, boolean canSendThrottled, PeerAggregation agg) {
    preProcessPeer(pn);
    if (pn.isConnected()) {
      handleConnectedPeer(pn, now, canSendThrottled, agg);
    } else {
      handleDisconnectedPeer(pn, now, agg);
    }
    updatePeerTiming(pn, agg);
  }

  private void preProcessPeer(PeerNode pn) {
    lastReceivedPacketFromAnyNode.accumulateAndGet(pn.lastReceivedPacketTime(), Math::max);
    pn.maybeOnConnect();
    if (pn.shouldDisconnectAndRemoveNow() && !pn.isDisconnecting()) {
      node.network().peers().messenger().disconnectAndRemove(pn, true, true, false);
    }
  }

  private void handleConnectedPeer(
      PeerNode pn, long now, boolean canSendThrottled, PeerAggregation agg) {
    boolean shouldThrottle = pn.shouldThrottle();
    pn.checkForLostPackets();

    if (isNodeDead(now, pn)) {
      pn.disconnected(true, false);
      return;
    }
    if (shouldDisconnectDueToAcks(now, pn)) {
      node.network()
          .peers()
          .messenger()
          .disconnect(pn, true, true, false, true, false, SECONDS.toMillis(5));
      return;
    }
    if (pn.isRoutable() && pn.noLongerRoutable()) {
      pn.invalidate();
      LOG.info("Mark peer incompatible (no longer routable): {}", pn);
      return;
    }

    if (canSendThrottled || !shouldThrottle) {
      considerUrgentSend(now, pn, agg);
    } else {
      considerAck(now, pn, agg);
    }

    if (canSendThrottled || !shouldThrottle) {
      long urgentTime = pn.getNextUrgentTime(now);
      if (urgentTime < Long.MAX_VALUE && LOG.isDebugEnabled())
        LOG.debug("Next urgent time {} ms (in {} ms) for {}", urgentTime, urgentTime - now, pn);
      agg.nextActionTime = Math.min(agg.nextActionTime, urgentTime);
    } else {
      agg.nextActionTime = Math.min(agg.nextActionTime, pn.timeCheckForLostPackets());
    }
  }

  private static void considerAck(long now, PeerNode pn, PeerAggregation agg) {
    long ackTime = pn.timeSendAcks();
    if (ackTime != Long.MAX_VALUE && ackTime <= now) {
      if (ackTime < agg.lowestAckTime) {
        agg.lowestAckTime = ackTime;
        if (agg.ackPeers != null) agg.ackPeers.clear();
        else agg.ackPeers = new ArrayList<>();
      }
      if (ackTime <= agg.lowestAckTime) agg.ackPeers.add(pn);
    }
  }

  private static void handleDisconnectedPeer(PeerNode pn, long now, PeerAggregation agg) {
    if (pn.noContactDetails()) pn.startARKFetcher();
    long handshakeTime = pn.timeSendHandshake(now);
    if (handshakeTime != Long.MAX_VALUE) {
      if (handshakeTime < agg.lowestHandshakeTime) {
        agg.lowestHandshakeTime = handshakeTime;
        if (agg.handshakePeers != null) agg.handshakePeers.clear();
        else agg.handshakePeers = new ArrayList<>();
      }
      if (handshakeTime <= agg.lowestHandshakeTime) agg.handshakePeers.add(pn);
    }
  }

  private static void updatePeerTiming(PeerNode pn, PeerAggregation agg) {
    long tempNow = System.currentTimeMillis();
    if ((tempNow - agg.oldTempNow) > SECONDS.toMillis(5)) {
      LOG.atError()
          .addArgument(tempNow - agg.oldTempNow)
          .addArgument(pn::userToString)
          .log("Time gap {} ms exceeds 5000 ms (peer={})");
    }
    agg.oldTempNow = tempNow;
  }

  private static boolean isNodeDead(long now, PeerNode pn) {
    if (now - pn.lastReceivedDataPacketTime() > pn.maxTimeBetweenReceivedPackets()) {
      LOG.info("Disconnect peer due to inactivity (no packets): {}", pn);
      return true;
    }
    return false;
  }

  private static boolean shouldDisconnectDueToAcks(long now, PeerNode pn) {
    if (now - pn.lastReceivedAckTime() > pn.maxTimeBetweenReceivedAcks() && !pn.isDisconnecting()) {
      LOG.info("Disconnect peer due to missing acks: {}", pn);
      return true;
    }
    return false;
  }

  private static void considerUrgentSend(long now, PeerNode pn, PeerAggregation agg) {
    long sendTime = pn.getNextUrgentTime(now);
    if (sendTime == Long.MAX_VALUE) return;
    if (sendTime <= now) {
      recordUrgentPeer(sendTime, pn, agg);
      return;
    }
    if (!pn.fullPacketQueued()) return;
    recordFullPacketPeer(sendTime, pn, agg);
  }

  private static void recordUrgentPeer(long sendTime, PeerNode pn, PeerAggregation agg) {
    if (sendTime < agg.lowestUrgentSendTime) {
      agg.lowestUrgentSendTime = sendTime;
      if (agg.urgentSendPeers != null) agg.urgentSendPeers.clear();
      else agg.urgentSendPeers = new ArrayList<>();
    }
    if (sendTime <= agg.lowestUrgentSendTime) agg.urgentSendPeers.add(pn);
  }

  private static void recordFullPacketPeer(long sendTime, PeerNode pn, PeerAggregation agg) {
    if (sendTime < agg.lowestFullPacketSendTime) {
      agg.lowestFullPacketSendTime = sendTime;
      if (agg.urgentFullPacketPeers != null) agg.urgentFullPacketPeers.clear();
      else agg.urgentFullPacketPeers = new ArrayList<>();
    }
    if (sendTime <= agg.lowestFullPacketSendTime) agg.urgentFullPacketPeers.add(pn);
  }

  private static final class Selection {
    PeerNode toSendPacket;
    PeerNode toSendAckOnly;
    PeerNode toSendHandshake;
  }

  private Selection selectNextAction(long now, PeerAggregation agg) {
    Selection sel = new Selection();
    long t = Long.MAX_VALUE;

    if (agg.lowestUrgentSendTime <= now && agg.urgentSendPeers != null) {
      sel.toSendPacket = agg.urgentSendPeers.get(localRandom.nextInt(agg.urgentSendPeers.size()));
      t = agg.lowestUrgentSendTime;
    } else if (agg.lowestFullPacketSendTime < Long.MAX_VALUE && agg.urgentFullPacketPeers != null) {
      sel.toSendPacket =
          agg.urgentFullPacketPeers.get(localRandom.nextInt(agg.urgentFullPacketPeers.size()));
      t = agg.lowestFullPacketSendTime;
    } else if (agg.lowestAckTime <= now && agg.ackPeers != null) {
      sel.toSendAckOnly = agg.ackPeers.get(localRandom.nextInt(agg.ackPeers.size()));
      t = agg.lowestAckTime;
    }

    if (agg.lowestHandshakeTime <= now
        && t > agg.lowestHandshakeTime
        && agg.handshakePeers != null) {
      sel.toSendHandshake = agg.handshakePeers.get(localRandom.nextInt(agg.handshakePeers.size()));
      sel.toSendPacket = null;
      sel.toSendAckOnly = null;
    }
    return sel;
  }

  private void performSelection(long now, Selection sel, PeerAggregation agg) {
    if (sel.toSendPacket != null) {
      if (sel.toSendPacket.maybeSendPacket(now, false)) {
        agg.nextActionTime = now;
      }
    } else if (sel.toSendAckOnly != null && sel.toSendAckOnly.maybeSendPacket(now, true)) {
      agg.nextActionTime = now;
    }

    if (sel.toSendHandshake != null) {
      long beforeHandshakeTime = System.currentTimeMillis();
      sel.toSendHandshake.getOutgoingMangler().sendHandshake(sel.toSendHandshake, false);
      long afterHandshakeTime = System.currentTimeMillis();
      if ((afterHandshakeTime - beforeHandshakeTime) > SECONDS.toMillis(2))
        LOG.atError()
            .addArgument(afterHandshakeTime - beforeHandshakeTime)
            .addArgument(() -> sel.toSendHandshake.userToString())
            .log("Peer handshake send duration {} ms exceeds 2000 ms (peer={})");
    }
  }

  private void updateNextActionFromAggregates(PeerAggregation agg) {
    agg.nextActionTime = Math.min(agg.nextActionTime, agg.lowestUrgentSendTime);
    agg.nextActionTime = Math.min(agg.nextActionTime, agg.lowestFullPacketSendTime);
    agg.nextActionTime = Math.min(agg.nextActionTime, agg.lowestAckTime);
    agg.nextActionTime = Math.min(agg.nextActionTime, agg.lowestHandshakeTime);
  }

  private void processOldOpennetPeers(long now) {
    // If we send something, we will have to go around the loop again.
    // Optimization possibility: Track the second best and check how many are in the array.
    OpennetManager om = node.network().opennet();
    if (om == null || node.network().uptime() <= SECONDS.toMillis(30)) return;

    OpennetPeerNode[] peers = om.getOldPeers();
    for (OpennetPeerNode pn : peers) {
      long lastConnected = pn.timeLastConnected(now);
      if (lastConnected <= 0) LOG.error("Old opennet peer lastConnected <= 0 (peer={})", pn);

      if (now - lastConnected > OpennetManager.MAX_TIME_ON_OLD_OPENNET_PEERS) {
        om.purgeOldOpennetPeer(pn);
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Remove old opennet peer: {} age={}", pn, TimeUtil.formatTime(now - lastConnected));
      } else if (!pn.isConnected()) {
        if (pn.noContactDetails()) {
          pn.startARKFetcher();
        } else if (pn.shouldSendHandshake()) {
          sendOpennetHandshake(pn);
        }
      }
    }
  }

  private static void sendOpennetHandshake(OpennetPeerNode pn) {
    long beforeHandshakeTime = System.currentTimeMillis();
    pn.getOutgoingMangler().sendHandshake(pn, true);
    long afterHandshakeTime = System.currentTimeMillis();
    if ((afterHandshakeTime - beforeHandshakeTime) > SECONDS.toMillis(2))
      LOG.atError()
          .addArgument(afterHandshakeTime - beforeHandshakeTime)
          .addArgument(pn::userToString)
          .log("Opennet handshake send duration {} ms exceeds 2000 ms (peer={})");
  }

  @SuppressWarnings("java:S2142")
  private void sleepUntilNextAction(long nowBeforeSend, long nextActionTime) {
    if (stopping) return;
    long now = System.currentTimeMillis();
    if ((now - nowBeforeSend) > SECONDS.toMillis(10))
      LOG.error("Loop delay {} ms exceeds 10000 ms in PacketSender", now - nowBeforeSend);

    long sleepTime = Math.min(nextActionTime - now, MAX_COALESCING_DELAY);

    if ((now - node.getStartupTime()) > MINUTES.toMillis(5)
        && (now - lastReceivedPacketFromAnyNode.get()) > Node.ALARM_TIME) {
      LOG.error(
          "No packets received from any node in {} seconds",
          SECONDS.convert(Node.ALARM_TIME, MILLISECONDS));
      lastReportedNoPackets = now;
    }

    if (sleepTime > 0) {
      if (LOG.isDebugEnabled()) LOG.debug("Sleep {} ms", sleepTime);
      final long deadline = System.currentTimeMillis() + sleepTime;
      synchronized (this) {
        long remaining;
        try {
          while (!wakeUpRequested
              && !stopping
              && (remaining = deadline - System.currentTimeMillis()) > 0) {
            wait(remaining);
          }
        } catch (InterruptedException _) {
          // Swallow to treat interrupt as a wake-up without latching the flag.
        }
        wakeUpRequested = false;
      }
    } else {
      if (LOG.isTraceEnabled())
        LOG.trace("Next urgent time is {} ms in the past", now - nextActionTime);
    }
  }

  /**
   * Notifies the sender to re‑check pending work.
   *
   * <p>Signals the monitor used by {@link #sleepUntilNextAction(long, long)} so the thread can
   * resume early and decide whether to send immediately.
   */
  void wakeUp() {
    // Wake up if needed
    synchronized (this) {
      wakeUpRequested = true;
      notifyAll();
    }
  }

  /**
   * Returns a localized message for PacketSender keys.
   *
   * @param key message key under the {@code PacketSender.} namespace
   * @param patterns substitution patterns; may be {@code null}
   * @param values substitution values; may be {@code null}
   * @return localized string resolved from the node resource bundle
   */
  protected String l10n(String key, String[] patterns, String[] values) {
    return NodeL10n.getBase().getString("PacketSender." + key, patterns, values);
  }

  /**
   * Returns a localized message for a single pattern/value pair.
   *
   * @param key message key under the {@code PacketSender.} namespace
   * @param pattern placeholder pattern
   * @param value value to substitute for the pattern
   * @return localized string resolved from the node resource bundle
   */
  protected String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString("PacketSender." + key, pattern, value);
  }
}
