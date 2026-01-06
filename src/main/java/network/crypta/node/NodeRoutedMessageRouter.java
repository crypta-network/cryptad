package network.crypta.node;

import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.support.ShortBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Handles routed-to-node messages and periodically prunes stale routed contexts. */
final class NodeRoutedMessageRouter implements Runnable {

  /** Milliseconds after which a routed context expires and can be removed. */
  private static final long STALE_CONTEXT = 20000;

  /** Milliseconds between successive prune checks for stale routed contexts. */
  private static final long STALE_CONTEXT_CHECK = 20000;

  private static final Logger LOG = LoggerFactory.getLogger(NodeRoutedMessageRouter.class);

  private final Node node;
  private final Map<Long, RoutedContext> routedContexts = new ConcurrentHashMap<>();
  private NodeStats nodeStats;

  NodeRoutedMessageRouter(Node node) {
    this.node = node;
    this.nodeStats = node.network().stats();
    node.network().ticker().queueTimedJob(this, STALE_CONTEXT_CHECK);
  }

  void start(NodeStats stats) {
    this.nodeStats = stats;
  }

  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (spec == DMT.FNPRoutedPing) {
      handleRouted(m, source);
      return true;
    } else if (spec == DMT.FNPRoutedPong) {
      return handleRoutedReply(m);
    } else if (spec == DMT.FNPRoutedRejected) {
      return handleRoutedRejected(m);
    }
    return false;
  }

  /** Prunes stale routed contexts and reschedules the next check. */
  @Override
  public void run() {
    long now = System.currentTimeMillis();
    routedContexts.values().removeIf(rc -> now - rc.createdTime > STALE_CONTEXT);
    node.network().ticker().queueTimedJob(this, STALE_CONTEXT_CHECK);
  }

  /** Handle a routed rejection (FNPRoutedRejected). */
  private boolean handleRoutedRejected(Message m) {
    if (!node.enableRoutedPing()) return true;
    long id = m.getLong(DMT.UID);
    RoutedContext rc = routedContexts.get(id);
    if (rc == null) {
      // No matching context; likely expired or local.
      LOG.error("Unrecognized FNPRoutedRejected; missing context");
      return false; // locally originated??
    }
    short htl = rc.lastHtl;
    if (rc.source != null) htl = rc.source.decrementHTL(htl);
    short ohtl = m.getShort(DMT.HTL);
    if (ohtl < htl) htl = ohtl;
    if (htl == 0) {
      // Equivalent to DNF.
      // Relay.
      if (rc.source != null) {
        try {
          rc.source
              .transport()
              .sendAsync(
                  DMT.createFNPRoutedRejected(id, (short) 0), null, nodeStats.routedMessageCtr);
        } catch (NotConnectedException _) {
          LOG.error("Relay of probe DNF failed; peer disconnected: {}", rc.source);
        }
      }
    } else {
      // Try routing to the next node
      forward(rc.msg, id, rc.source, htl, rc.msg.getDouble(DMT.TARGET_LOCATION), rc, rc.identity);
    }
    return true;
  }

  /**
   * Handles a routed message received by the dispatcher.
   *
   * @param m message to route
   * @param source optional source peer, or {@code null} for local originators
   */
  void handleRouted(Message m, PeerNode source) {
    if (!node.enableRoutedPing()) return;
    if (LOG.isDebugEnabled()) LOG.debug("Handle routed message: {}", m);

    long id = m.getLong(DMT.UID);
    short htl = m.getShort(DMT.HTL);
    byte[] identity = ((ShortBuffer) m.getObject(DMT.NODE_IDENTITY)).getData();
    if (source != null) htl = source.decrementHTL(htl);

    if (rejectDuplicateRoutedIfAny(id, htl, source, m)) return;

    RoutedContext ctx = new RoutedContext(m, source, identity);
    routedContexts.put(id, ctx);

    double target = m.getDouble(DMT.TARGET_LOCATION);
    if (LOG.isDebugEnabled())
      LOG.debug("Routed id={} from {} htl={} target={}", id, source, htl, target);
    processRoutedDispatchOrForward(m, source, id, htl, target, ctx, identity);
  }

  private boolean rejectDuplicateRoutedIfAny(long id, short htl, PeerNode source, Message m) {
    RoutedContext ctx = routedContexts.get(id);
    if (ctx == null) return false;
    try {
      source
          .transport()
          .sendAsync(DMT.createFNPRoutedRejected(id, htl), null, nodeStats.routedMessageCtr);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Lost connection rejecting {}", m);
    }
    return true;
  }

  private void processRoutedDispatchOrForward(
      Message m,
      PeerNode source,
      long id,
      short htl,
      double target,
      RoutedContext ctx,
      byte[] identity) {
    if (isLocalTarget(target)) {
      if (LOG.isDebugEnabled())
        LOG.debug("Dispatching {} on {}", m.getSpec(), node.network().darknetPortNumber());
      dispatchRoutedMessage(m, source, id);
      return;
    }
    if (htl == 0) {
      sendRoutedReject(source, id, m);
      return;
    }
    forward(m, id, source, htl, target, ctx, identity);
  }

  private boolean isLocalTarget(double target) {
    return Math.abs(node.network().locationManager().getLocation() - target)
        <= Double.MIN_VALUE; // exact match
  }

  private void sendRoutedReject(PeerNode source, long id, Message m) {
    Message reject = DMT.createFNPRoutedRejected(id, (short) 0);
    if (source != null)
      try {
        source.transport().sendAsync(reject, null, nodeStats.routedMessageCtr);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled()) LOG.debug("Lost connection while sending reject for {}", m);
      }
  }

  boolean handleRoutedReply(Message m) {
    if (!node.enableRoutedPing()) return true;
    long id = m.getLong(DMT.UID);
    if (LOG.isDebugEnabled()) LOG.debug("Received routed reply: {}", m);
    RoutedContext ctx = routedContexts.get(id);
    if (ctx == null) {
      LOG.error("Unrecognized routed reply: {}", m);
      return false;
    }
    PeerNode pn = ctx.source;
    if (pn == null) return false;
    try {
      pn.transport().sendAsync(m.cloneAndDropSubMessages(), null, nodeStats.routedMessageCtr);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Lost connection while forwarding {} to {}", m, pn);
    }
    return true;
  }

  private void forward(
      Message m,
      long id,
      PeerNode pn,
      short htl,
      double target,
      RoutedContext ctx,
      byte[] targetIdentity) {
    if (LOG.isDebugEnabled()) LOG.debug("Evaluate forwarding decision");
    m = preForward(m, htl);
    while (true) {
      PeerNode next = selectNextHop(pn, htl, target, ctx, targetIdentity);
      if (LOG.isDebugEnabled()) LOG.debug("Next hop={} message={}", next, m);
      if (next != null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Forward {} to {}", m.getSpec(), next.getPeer().getPort());
        ctx.addSent(next);
        if (!trySendToNext(next, m)) continue;
      } else {
        sendDeadEndReject(pn, id, htl, m);
      }
      return;
    }
  }

  private PeerNode selectNextHop(
      PeerNode pn, short htl, double target, RoutedContext ctx, byte[] targetIdentity) {
    PeerNode next = node.network().peers().getByPubKeyHash(targetIdentity);
    if (next != null && !next.isConnected()) {
      LOG.error("Target found but disconnected: {}", next);
      next = null;
    }
    if (next == null)
      next =
          node.network()
              .peers()
              .routingSelector()
              .closerPeer(
                  pn,
                  ctx.routedTo,
                  target,
                  true,
                  node.isAdvancedModeEnabled(),
                  -1,
                  null,
                  null,
                  htl,
                  0,
                  pn == null,
                  false,
                  false);
    return next;
  }

  private boolean trySendToNext(PeerNode next, Message m) {
    try {
      next.transport().sendAsync(m, null, nodeStats.routedMessageCtr);
      return true;
    } catch (NotConnectedException _) {
      return false;
    }
  }

  private void sendDeadEndReject(PeerNode pn, long id, short htl, Message m) {
    if (LOG.isDebugEnabled())
      LOG.debug("Reach dead end for {} on {}", m.getSpec(), node.network().darknetPortNumber());
    Message reject = DMT.createFNPRoutedRejected(id, htl);
    if (pn != null)
      try {
        pn.transport().sendAsync(reject, null, nodeStats.routedMessageCtr);
      } catch (NotConnectedException _) {
        LOG.error("Send reject back to source {} failed", pn);
      }
  }

  /** Prepare a routed-to-node message for forwarding. */
  private Message preForward(Message m, short newHTL) {
    m = m.cloneAndDropSubMessages();
    m.set(DMT.HTL, newHTL); // update htl
    if (m.getSpec() == DMT.FNPRoutedPing) {
      int x = m.getInt(DMT.COUNTER);
      x++;
      m.set(DMT.COUNTER, x);
    }
    return m;
  }

  /**
   * Deal with a routed-to-node message that landed on this node. This is where
   * message-type-specific code executes.
   *
   * @param m The message to dispatch
   * @param src The source peer node
   * @param id The message ID
   */
  private void dispatchRoutedMessage(Message m, PeerNode src, long id) {
    if (m.getSpec() == DMT.FNPRoutedPing) {
      if (LOG.isDebugEnabled()) LOG.debug("RoutedPing reaches target ({})", id);
      int x = m.getInt(DMT.COUNTER);
      Message reply = DMT.createFNPRoutedPong(id, x);
      if (LOG.isDebugEnabled()) LOG.debug("Reply routed pong; counter={} id={}", x, id);
      try {
        src.transport().sendAsync(reply, null, nodeStats.routedMessageCtr);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled())
          LOG.debug("Lost connection while replying to {} in dispatchRoutedMessage", m);
      }
    }
  }

  /** Per-UID state for routed message handling. */
  static class RoutedContext {
    final HashSet<PeerNode> routedTo;
    final byte[] identity;
    long createdTime;
    long accessTime;
    PeerNode source;
    Message msg;
    short lastHtl;

    RoutedContext(Message msg, PeerNode source, byte[] identity) {
      createdTime = accessTime = System.currentTimeMillis();
      this.source = source;
      routedTo = new HashSet<>();
      this.msg = msg;
      lastHtl = msg.getShort(DMT.HTL);
      this.identity = identity;
    }

    // Tracks peers the message has been forwarded to; used to avoid loops when choosing next hop.
    void addSent(PeerNode n) {
      routedTo.add(n);
    }
  }
}
