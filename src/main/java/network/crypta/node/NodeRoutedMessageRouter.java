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

/**
 * Routes routed-to-node probe messages through the node and manages per-request state.
 *
 * <p>This router accepts routed ping/pong/rejection messages, tracks the per-UID context needed to
 * forward replies, and periodically prunes contexts that have aged beyond a fixed timeout. Typical
 * usage is: construct once per {@link Node} instance, allow the dispatcher to call {@link
 * #handle(Message, PeerNode)} for incoming traffic, and rely on the router to reschedule its own
 * pruning via the node ticker.
 *
 * <p>State is intentionally minimal: contexts are keyed by UID, store the origin peer (if any), and
 * record which peers have already been tried to avoid routing loops. The router treats exact
 * location matches as terminal and dispatches locally; otherwise it forwards to a selected peer or
 * returns a rejection when no path remains. Contexts expire after a fixed wall-clock delay to keep
 * memory bounded and to prevent stale replies from being misrouted.
 *
 * <p>Thread-safety: contexts are stored in a {@link ConcurrentHashMap}, but message handling is
 * still single-request oriented. Callers should avoid invoking {@link #handle(Message, PeerNode)}
 * concurrently for the same UID because later arrivals may be rejected as duplicates. The periodic
 * prune job runs on the ticker thread and is safe with concurrent lookups.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Accepting routed pings and deciding between local dispatch or forwarding.
 *   <li>Forwarding routed replies back to their origin peer when possible.
 *   <li>Propagating routed rejections with updated HTL semantics.
 *   <li>Cleaning up stale routed contexts to bound memory use.
 * </ul>
 *
 * @see Node
 * @see NodeStats
 * @see Message
 * @see DMT
 */
final class NodeRoutedMessageRouter implements Runnable {

  /** Milliseconds after which a routed context expires and can be removed. */
  private static final long STALE_CONTEXT = 20000;

  /** Milliseconds between successive prune checks for stale routed contexts. */
  private static final long STALE_CONTEXT_CHECK = 20000;

  /** Logger for routed message handling diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(NodeRoutedMessageRouter.class);

  /** The owning node used for network access and configuration. */
  private final Node node;

  /** Per-UID routed contexts used to forward replies and detect duplicates. */
  private final Map<Long, RoutedContext> routedContexts = new ConcurrentHashMap<>();

  /** Node statistics for accounting routed message bytes. */
  private NodeStats nodeStats;

  /**
   * Creates a routed message router and schedules the first prune task.
   *
   * <p>The router binds to the provided node, captures its current {@link NodeStats}, and queues a
   * timed job on the node's ticker to prune stale contexts. This constructor does not start routing
   * by itself; callers should wire the router into the dispatcher so that {@link #handle(Message,
   * PeerNode)} is invoked for routed probe traffic.
   *
   * @param node owning node instance used for configuration and network access; must be non-null
   */
  NodeRoutedMessageRouter(Node node) {
    this.node = node;
    this.nodeStats = node.network().stats();
    node.network().ticker().queueTimedJob(this, STALE_CONTEXT_CHECK);
  }

  /**
   * Updates the {@link NodeStats} reference used for routed message accounting.
   *
   * <p>This is typically invoked during node startup when stats are initialized or replaced. The
   * method performs a simple reference swap and does not touch existing routed contexts. Passing a
   * {@code null} reference is not supported because send operations expect a non-null counter.
   *
   * @param stats stats instance used to account routed message bytes; must be non-null
   */
  void start(NodeStats stats) {
    this.nodeStats = stats;
  }

  /**
   * Handles routed probe messages and dispatches to the appropriate subtype handler.
   *
   * <p>The method examines the message type and handles routed ping, pong, or rejection messages.
   * Unknown message types return {@code false} so the caller can fall back to other handlers. When
   * routing is disabled, the method returns {@code true} to signal that the message was consumed
   * (even though no action is taken), matching the router's role as the owner of these types.
   *
   * @param m routed probe message to handle; must be non-null and fully populated
   * @param source peer the message arrived from, or {@code null} for local originators
   * @return {@code true} if the message type was handled or intentionally ignored
   */
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

  /**
   * Handles a routed rejection (FNPRoutedRejected) and decides whether to relay or re-route.
   *
   * <p>The method locates the matching {@link RoutedContext} by UID. If no context exists, the
   * rejection likely refers to an expired or local request and the method returns {@code false}.
   * Otherwise, the HTL is updated by applying the source peer's decrement rules and clamping to the
   * incoming rejection's HTL. An HTL of zero triggers a relay rejection back to the source; a
   * positive HTL attempts to forward to another peer.
   *
   * @param m routed rejection message containing UID and remaining HTL; must be non-null
   * @return {@code true} when processed or ignored due to routing disabled; {@code false} if the
   *     context is missing and no relay is possible
   */
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

  /**
   * Detects duplicate routed messages and rejects them back to the source when appropriate.
   *
   * <p>This method checks the UID map for an existing context. When a duplicate is detected, it
   * responds with an {@code FNPRoutedRejected} that carries the current HTL value and returns
   * {@code true} to stop further processing. If no context is present, it returns {@code false} so
   * the caller can proceed with normal routing.
   *
   * @param id routed request UID to check for duplicates
   * @param htl current hops-to-live value to include in any rejection
   * @param source peer that sent the duplicate message; must be non-null to send a rejection
   * @param m original routed message used for diagnostic logging
   * @return {@code true} if a duplicate was detected and rejected; {@code false} otherwise
   */
  private boolean rejectDuplicateRoutedIfAny(long id, short htl, PeerNode source, Message m) {
    RoutedContext ctx = routedContexts.get(id);
    if (ctx == null) return false;
    if (source == null) return true;
    try {
      source
          .transport()
          .sendAsync(DMT.createFNPRoutedRejected(id, htl), null, nodeStats.routedMessageCtr);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Lost connection rejecting {}", m);
    }
    return true;
  }

  /**
   * Decides between local dispatch, rejection, or forwarding for a routed message.
   *
   * <p>If the target location exactly matches the local node, the message is dispatched locally.
   * Otherwise, a zero HTL triggers a rejection back to the source (if any). When HTL is positive,
   * the message is forwarded using the routing selection flow and the routed context.
   *
   * @param m routed message to handle; must be non-null
   * @param source source peer that sent the message or {@code null} if locally originated
   * @param id routed request UID extracted from the message
   * @param htl current hops-to-live value after any source adjustments
   * @param target target location for routing decisions
   * @param ctx routed context used to track forwarding state
   * @param identity target identity bytes used for direct peer lookup
   */
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

  /**
   * Determines whether the given target location matches the local node's location exactly.
   *
   * <p>This comparison uses an absolute difference test against {@link Double#MIN_VALUE} to
   * represent an exact match on the location ring. Callers should treat {@code true} as a signal to
   * dispatch locally and {@code false} as permission to continue routing.
   *
   * @param target target location value from the routed message
   * @return {@code true} if the target location is exactly local; {@code false} otherwise
   */
  private boolean isLocalTarget(double target) {
    return Math.abs(node.network().locationManager().getLocation() - target)
        <= Double.MIN_VALUE; // exact match
  }

  /**
   * Sends a routed rejection back to the source peer when a request cannot be forwarded.
   *
   * <p>This method is used for HTL exhaustion or dead-end routing outcomes. It is a best-effort
   * operation: a disconnected source simply results in a debug log. A {@code null} source implies a
   * locally originated request, in which case no rejection is sent.
   *
   * @param source peer to notify, or {@code null} for locally originated requests
   * @param id routed request UID to include it in the rejection payload
   * @param m original routed message, used only for diagnostic logging
   */
  private void sendRoutedReject(PeerNode source, long id, Message m) {
    Message reject = DMT.createFNPRoutedRejected(id, (short) 0);
    if (source != null)
      try {
        source.transport().sendAsync(reject, null, nodeStats.routedMessageCtr);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled()) LOG.debug("Lost connection while sending reject for {}", m);
      }
  }

  /**
   * Forwards a routed reply (FNPRoutedPong) back to the recorded origin peer.
   *
   * <p>UID looks up the reply in the routed context map. If no context exists, the method logs an
   * error and returns {@code false} so callers can observe that the reply was unexpected. When a
   * context exists but has no source (locally originated), the method returns {@code false} without
   * sending any message. Forwarding clones and strips sub-messages to avoid metadata leakage.
   *
   * @param m routed reply message containing UID and payload; must be non-null
   * @return {@code true} if the reply was forwarded; {@code false} otherwise
   */
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

  /**
   * Forwards a routed message to the next hop or reports a dead-end rejection.
   *
   * <p>The method prepares the message for forwarding, then repeatedly selects the next hop, and
   * attempts to send it. If a candidate is disconnected, selection repeats. When no candidate
   * exists, a rejection is sent to the source peer if present.
   *
   * @param m original routed message; must be non-null
   * @param id routed request UID used for rejections
   * @param pn origin peer for the request, or {@code null} for local originators
   * @param htl current hops-to-live for the outgoing message
   * @param target target location on the location ring
   * @param ctx routed context used to track which peers have been tried
   * @param targetIdentity target identity bytes used for direct peer lookup
   */
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

  /**
   * Selects the next hop peer for a routed request based on identity or routing heuristics.
   *
   * <p>The method first attempts a direct lookup by target identity and validates connectivity.
   * When no direct target is eligible, it delegates to the routing selector with the current
   * routed-to set and HTL. The selection is purely advisory; callers must still handle a {@code
   * null} result and update the routed context when a peer is chosen.
   *
   * @param pn origin peer for the request, or {@code null} for local originators
   * @param htl current hops-to-live value used by routing heuristics
   * @param target target location on the location ring
   * @param ctx routed context holding previously selected peers
   * @param targetIdentity target identity bytes used for direct peer lookup
   * @return the chosen peer, or {@code null} if no eligible peer was found
   */
  private PeerNode selectNextHop(
      PeerNode pn, short htl, double target, RoutedContext ctx, byte[] targetIdentity) {
    PeerNode next = node.network().peers().getByPubKeyHash(targetIdentity);
    if (next != null && !next.isConnected()) {
      LOG.error("Target found but disconnected: {}", next);
      next = null;
    }
    if (next == null) {
      PeerRoutingSelectionParams params =
          new PeerRoutingSelectionParams(
              pn,
              ctx.routedTo,
              target,
              true,
              node.isAdvancedModeEnabled(),
              -1,
              null,
              2.0,
              null,
              htl,
              0L,
              pn == null,
              false,
              null,
              false,
              System.currentTimeMillis(),
              false);
      next = node.network().peers().routingSelector().closerPeer(params);
    }
    return next;
  }

  /**
   * Sends a routed message to the chosen next hop.
   *
   * <p>The sending is asynchronous and may fail immediately if the peer is disconnected. In that
   * case the caller is expected to retry selection. This method does not mutate the state beyond
   * the attempted sending and never throws on connection failure.
   *
   * @param next selected next hop peer; must be non-null
   * @param m message to send; must be non-null and fully populated
   * @return {@code true} if the sending was enqueued; {@code false} if the peer was disconnected
   */
  private boolean trySendToNext(PeerNode next, Message m) {
    try {
      next.transport().sendAsync(m, null, nodeStats.routedMessageCtr);
      return true;
    } catch (NotConnectedException _) {
      return false;
    }
  }

  /**
   * Sends a routed rejection when no eligible next hop exists.
   *
   * <p>This is a best-effort notification to the origin peer. If the origin peer is {@code null}
   * (locally originated), the method performs no send. Connection failures are logged at the error
   * level because the rejection could not be delivered.
   *
   * @param pn origin peer to notify, or {@code null} for local originators
   * @param id routed request UID to include in the rejection
   * @param htl remaining hops-to-live to report in the rejection
   * @param m original message used for diagnostic logging
   */
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

  /**
   * Prepares a routed-to-node message for forwarding by cloning and updating fields.
   *
   * <p>The method clones the message while dropping any sub-messages, updates the HTL field, and
   * increments the routed ping counter when applicable. The cloned message is safe for forwarding
   * because it strips sub-message metadata that could leak routing context.
   *
   * @param m original routed message to forward; must be non-null
   * @param newHTL updated hops-to-live value to store in the forwarded message
   * @return a cloned message with updated HTL and counter-fields
   */
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
      if (src == null) {
        node.network().usm().checkFilters(reply, null);
        return;
      }
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
    /** Peers already selected for this UID, used to avoid routing loops. */
    final HashSet<PeerNode> routedTo;

    /** Target identity bytes used for direct peer lookup when available. */
    final byte[] identity;

    /** Creation timestamp in milliseconds since epoch; used for expiry checks. */
    long createdTime;

    /** Last access timestamp in milliseconds since epoch; currently informational. */
    long accessTime;

    /** Origin peer for this routed request, or {@code null} for local originators. */
    PeerNode source;

    /** Original message associated with the route; retained for re-forwarding. */
    Message msg;

    /** Last observed HTL for this request, before rejection or forwarding adjustments. */
    short lastHtl;

    /**
     * Creates a routed context for a specific message UID.
     *
     * <p>The constructor snapshots the creation time, source peer, and message fields needed for
     * later forwarding. The HTL is read directly from the message payload and is not adjusted for
     * routing decisions.
     *
     * @param msg routed message being processed; must be non-null and include {@link DMT#HTL}
     * @param source origin peer for the request, or {@code null} if locally originated
     * @param identity target identity bytes copied from the message; must be non-null
     */
    RoutedContext(Message msg, PeerNode source, byte[] identity) {
      createdTime = accessTime = System.currentTimeMillis();
      this.source = source;
      routedTo = new HashSet<>();
      this.msg = msg;
      lastHtl = msg.getShort(DMT.HTL);
      this.identity = identity;
    }

    // Tracks peers the message has been forwarded to; used to avoid loops when choosing the next
    // hop.
    /**
     * Records that a peer was selected as a forwarding target for this UID.
     *
     * <p>This is a simple set insert used by routing selection to avoid retrying the same peer. The
     * method does not check connectivity or attempt any send operations.
     *
     * @param n peer that was attempted as a next hop; must be non-null
     */
    void addSent(PeerNode n) {
      routedTo.add(n);
    }
  }
}
