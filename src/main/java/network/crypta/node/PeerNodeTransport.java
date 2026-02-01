package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.SocketHandler;
import network.crypta.io.xfer.PacketThrottle;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Transport and messaging helpers bound to a single {@link PeerNode} connection.
 *
 * <p>This class centralizes send/receive primitives for the peer link: it queues outbound messages,
 * provides blocking send behavior with bounded waits, and funnels inbound messages into the {@link
 * network.crypta.io.comm.MessageCore} filter/dispatch pipeline. Typical usage comes from the peer's
 * networking threads and handshaking flow, which call {@link #sendAsync(Message,
 * AsyncMessageCallback, ByteCounter)} for normal traffic, {@link #sendSync(Message, ByteCounter,
 * boolean)} for strict sequencing, and {@link #startProcessingDecryptedMessages(int)} for
 * per-packet decode batches.
 *
 * <p>State is mutable and scoped to a single peer instance; the class is not thread-safe on its own
 * and relies on {@link PeerNode} and queue synchronization where needed (for example, incrementing
 * resend counters). It trades immediate sender wakeup against packet coalescing to reduce overhead
 * while still honoring size thresholds.
 *
 * <ul>
 *   <li>Queues and accounts for outbound messages and resends.
 *   <li>Performs ping/handshake helper exchanges.
 *   <li>Groups decoded inbound messages for ordered handling.
 * </ul>
 *
 * @see PeerTransport
 * @see PeerNode
 * @see network.crypta.io.comm.MessageCore
 */
final class PeerNodeTransport implements PeerTransport {
  /** Logger for transport diagnostics and timeout warnings. */
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeTransport.class);

  /** Error tag used when constructing lightweight diagnostic exceptions. */
  private static final String STR_ERROR = "error";

  /** Separator used in log messages to keep peer identifiers readable. */
  private static final String STR_FOR = " for ";

  /** Owning peer for this transport; provides queues, stats, and crypto context. */
  private final PeerNode peer;

  /** Last throttle state used by the packet sender for this peer. */
  private final PacketThrottle lastThrottle = new PacketThrottle(Node.PACKET_SIZE);

  /** Cumulative resend bytes sent for this transport instance. */
  private long resendBytesSent;

  /** Counter that updates both the transport and node-wide resend byte totals. */
  private final ByteCounter resendByteCounter =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Ignore
        }

        @Override
        public void sentBytes(int x) {
          synchronized (peer) {
            resendBytesSent += x;
          }
          peer.node.network().stats().resendByteCounter.sentBytes(x);
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  /**
   * Creates a transport wrapper bound to a specific peer connection.
   *
   * <p>The instance holds mutable counters and uses the peer's message queue, node statistics, and
   * cryptographic context. Callers should reuse the same transport for the life of the peer session
   * to keep accounting consistent.
   *
   * @param peer owning peer instance; must be non-null and fully initialized
   */
  PeerNodeTransport(PeerNode peer) {
    this.peer = peer;
  }

  /**
   * Enqueues a message for asynchronous sending on the peer link.
   *
   * <p>The message is wrapped into a {@link MessageItem} and placed into the peer's message queue.
   * The queue estimate determines whether the packet sender is woken immediately or left to
   * coalesce traffic. If {@code ctr} is {@code null}, an error is logged, and the sending still
   * proceeds; callers should provide a counter to keep bandwidth accounting accurate. If the peer
   * is not connected, the callback is notified and a {@link NotConnectedException} is thrown.
   *
   * <pre>{@code
   * Message msg = DMT.createFNPPing(42);
   * transport.sendAsync(msg, null, node.getNodeStats().pingCounter);
   * }</pre>
   *
   * @param msg message to enqueue; must be locally constructed and non-null
   * @param cb callback notified on send lifecycle events; may be null
   * @param ctr byte counter for bandwidth accounting; null logs and proceeds
   * @return queued {@link MessageItem} for tracking or unqueueing later
   * @throws NotConnectedException if the peer is disconnected at enqueue time
   */
  @Override
  public MessageItem sendAsync(Message msg, AsyncMessageCallback cb, ByteCounter ctr)
      throws NotConnectedException {
    if (ctr == null)
      LOG.error(
          "ByteCounter null, so bandwidth usage cannot be logged. Refusing to send.",
          new Exception("debug"));
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Sending async: {} : {} on {}" + STR_FOR + "{} priority {}",
          msg,
          cb,
          peer,
          peer.node.network().darknetPortNumber(),
          msg.getPriority());
    if (!peer.isConnected()) {
      if (cb != null) cb.disconnected();
      throw new NotConnectedException();
    }
    if (msg.getSource() != null) {
      LOG.error(
          "Messages should NOT be relayed as-is, they should always be re-created to clear any"
              + " sub-messages etc, see comments in Message.java!: {}",
          msg,
          new Exception(STR_ERROR));
    }
    peer.incrementSentMessageType(msg.getSpec().getName());
    MessageItem item =
        new MessageItem(msg, cb == null ? null : new AsyncMessageCallback[] {cb}, ctr);
    long now = System.currentTimeMillis();
    peer.reportBackoffStatus(now);
    int maxSize = peer.getMaxPacketSize();
    int x = peer.getMessageQueue().queueAndEstimateSize(item, maxSize);
    if (x > maxSize || !peer.node.isEnablePacketCoalescing()) {
      // If there is a packet's worth to send, wake up the packetsender.
      peer.wakeUpSender();
    }
    // Otherwise we do not need to wake up the PacketSender
    // It will wake up before the maximum coalescing delay (100ms) because
    // it wakes up every 100ms *anyway*.
    return item;
  }

  /**
   * Sends a message and waits for completion with bounded timeouts.
   *
   * <p>This method enqueues the message and then waits up to one minute for the sending to
   * complete. On timeout, it attempts to un-queue the message; if un-queueing fails, it waits an
   * additional ten seconds before declaring a fatal timeout. The {@code realTime} flag is passed to
   * overload reporting so higher-priority paths can be treated differently by admission control.
   *
   * <pre>{@code
   * Message msg = DMT.createFNPPing(7);
   * transport.sendSync(msg, node.getNodeStats().pingCounter, true);
   * }</pre>
   *
   * @param req message to enqueue and send; must be non-null and locally constructed
   * @param ctr byte counter for bandwidth accounting; null logs and proceeds
   * @param realTime whether this sending is real-time for overload reporting
   * @throws NotConnectedException if the peer disconnects before completion
   * @throws SyncSendWaitedTooLongException if the sending does not complete in time
   */
  @Override
  public void sendSync(Message req, ByteCounter ctr, boolean realTime)
      throws NotConnectedException, SyncSendWaitedTooLongException {
    SyncMessageCallback cb = new SyncMessageCallback();
    MessageItem item = sendAsync(req, cb, ctr);
    cb.waitForSend(MINUTES.toMillis(1));
    if (!cb.done) {
      LOG.warn(
          "Waited too long for a blocking send for {} to {}",
          req,
          peer.selfPeerNode(),
          new Exception(STR_ERROR));
      peer.localRejectedOverload("SendSyncTimeout", realTime);
      // Try to un-queue it, since it presumably won't be of any use now.
      if (!peer.getMessageQueue().removeMessage(item)) {
        cb.waitForSend(SECONDS.toMillis(10));
        if (!cb.done) {
          LOG.error(
              "Waited too long for blocking send and then could not un-queue for {} to {}",
              req,
              peer.selfPeerNode(),
              new Exception(STR_ERROR));
          // Can't cancel yet, can't send it, something seriously wrong.
          // Treat as fatal timeout as probably their fault.
          // Note: We have already waited more than the no-messages timeout; do not wait again.
          peer.fatalTimeout();
          // Then throw the error.
        } else {
          return;
        }
      }
      throw new SyncSendWaitedTooLongException();
    }
  }

  /**
   * Sends a ping and waits briefly for a matching pong.
   *
   * <p>The method transmits a {@link DMT#FNPPing} with the provided sequence number, then waits up
   * to 2 seconds for a {@link DMT#FNPPong} carrying the same sequence. A {@code true} return value
   * indicates that a matching pong arrived in time. A {@code false} return means timeout without a
   * disconnect. If the connection drops while waiting, a {@link NotConnectedException} is thrown.
   *
   * @param pingID sequence number to embed and match in the response
   * @return {@code true} when a matching pong is received; {@code false} on timeout
   * @throws NotConnectedException if the peer disconnects while awaiting the pong
   */
  @Override
  public boolean ping(int pingID) throws NotConnectedException {
    Message ping = DMT.createFNPPing(pingID);
    peer.node.network().usm().send(peer, ping, peer.node.network().dispatcher().pingCounter);
    Message msg;
    try {
      msg =
          peer.node
              .network()
              .usm()
              .waitFor(
                  MessageFilter.create()
                      .setTimeout(2000)
                      .setType(DMT.FNPPong)
                      .setField(DMT.PING_SEQNO, pingID),
                  null);
    } catch (DisconnectedException _) {
      throw new NotConnectedException("Disconnected while waiting for pong");
    }
    return msg != null;
  }

  /**
   * Returns the packet throttle instance associated with this transport.
   *
   * <p>The returned throttle object is stable for the life of the transport and is owned by this
   * instance. Callers should treat it as a mutable shared state and avoid concurrent modification
   * without appropriate synchronization.
   *
   * @return throttle instance used for packet pacing on this link
   */
  @Override
  public PacketThrottle getThrottle() {
    return lastThrottle;
  }

  /**
   * Returns the socket handler used for outbound packets to this peer.
   *
   * <p>The handler comes from the peer's outgoing packet mangler and reflects the current socket
   * context for this link. The returned reference is not copied; callers should not retain it
   * beyond the lifetime of the peer connection.
   *
   * @return socket handler for outbound packet IO
   */
  @Override
  public SocketHandler getSocketHandler() {
    return peer.getOutgoingMangler().getSocketHandler();
  }

  /**
   * Hands a decoded message to the messaging core for filtering and dispatch.
   *
   * <p>This is the primary entry point for inbound message handling at the transport layer. It
   * delegates to {@link network.crypta.io.comm.MessageCore#checkFilters(Message,
   * network.crypta.io.comm.PacketSocketHandler)} using the peer's current socket, allowing any
   * waiting filters or dispatcher logic to process the message.
   *
   * @param m decoded message to handle; must be non-null and peer-associated
   */
  @Override
  public void handleMessage(Message m) {
    peer.node.network().usm().checkFilters(m, peer.crypto.getSocket());
  }

  /**
   * Starts a grouped decoding session for a batch of decrypted packets.
   *
   * <p>The returned {@link DecodingMessageGroup} collects decoded messages, immediately handling
   * peer-load status updates and deferring load-limited requests until after other messages. This
   * ordering reduces priority inversion while still honoring load control semantics.
   *
   * @param size expected number of messages; used only for internal list sizing
   * @return a new decoding group instance for the caller to use
   */
  @Override
  public DecodingMessageGroup startProcessingDecryptedMessages(int size) {
    return new DecodingMessageGroupImpl(size);
  }

  /**
   * Sends the initial post-handshake messages to a peer.
   *
   * <p>This includes location, detected IP, current time, routing status, and uptime. The location
   * notification is only sent on real connections. Any {@link NotConnectedException} is logged but
   * does not abort the post-handshake flow; {@link PeerNode#sendConnectedDiffNoderef()} is invoked
   * regardless to share updated noderef data.
   */
  void sendInitialMessages() {
    Message locMsg =
        DMT.createFNPLocChangeNotificationNew(
            peer.node.network().locationManager().getLocation(),
            peer.node.network().peers().getPeerLocationDoubles(true));
    Message ipMsg = DMT.createFNPDetectedIPAddress(peer.getPeer());
    Message timeMsg = DMT.createFNPTime(System.currentTimeMillis());
    Message dRoutingMsg = DMT.createRoutingStatus(!peer.disableRoutingHasBeenSetLocally);
    Message uptimeMsg =
        DMT.createFNPUptime((byte) (int) (100 * peer.node.network().uptimeEstimator().getUptime()));

    try {
      if (peer.isRealConnection())
        sendAsync(locMsg, null, peer.node.network().stats().initialMessagesCtr);
      sendAsync(ipMsg, null, peer.node.network().stats().initialMessagesCtr);
      sendAsync(timeMsg, null, peer.node.network().stats().initialMessagesCtr);
      sendAsync(dRoutingMsg, null, peer.node.network().stats().initialMessagesCtr);
      sendAsync(uptimeMsg, null, peer.node.network().stats().initialMessagesCtr);
    } catch (NotConnectedException e) {
      LOG.error(
          "Completed handshake with {} but disconnected ({}:{}!!!: {}",
          peer.getPeer(),
          peer.isConnected(),
          peer.getCurrentKeyTracker(),
          e,
          e);
    }

    peer.sendConnectedDiffNoderef();
  }

  /**
   * Sends a detected-IP change notification to the peer.
   *
   * <p>This is a best-effort message; if the peer is no longer connected, the attempt is logged and
   * silently dropped. Bandwidth accounting uses the node's IP-change counter.
   */
  void sendIPAddressMessage() {
    Message ipMsg = DMT.createFNPDetectedIPAddress(peer.getPeer());
    try {
      sendAsync(ipMsg, null, peer.node.network().stats().changedIPCtr);
    } catch (NotConnectedException e) {
      LOG.info("Sending IP change message to {} but disconnected: {}", peer, e, e);
    }
  }

  /**
   * Sends a node-to-node message constructed from a {@link SimpleFieldSet}.
   *
   * <p>The method mutates {@code fs} by setting {@code n2nType} and optionally {@code sentTime}.
   * For darknet peers with {@code queueOnNotConnected} enabled, the message is queued for later
   * replay and an unqueue-on-ack callback is attached. If the sending fails and a sent-time was
   * injected, that field is removed to avoid persisting a stale timestamp.
   *
   * @param fs field set serialized into the message body; mutated in place
   * @param n2nType node-to-node message type identifier to embed
   * @param includeSentTime whether to include a {@code sentTime} value
   * @param now timestamp in milliseconds since the epoch when the message is created
   * @param queueOnNotConnected whether to queue the message for darknet peers
   */
  void sendNodeToNodeMessage(
      SimpleFieldSet fs,
      int n2nType,
      boolean includeSentTime,
      long now,
      boolean queueOnNotConnected) {
    fs.putOverwrite("n2nType", Integer.toString(n2nType));
    if (includeSentTime) {
      fs.put("sentTime", now);
    }
    Message n2nm =
        DMT.createNodeToNodeMessage(n2nType, fs.toString().getBytes(StandardCharsets.UTF_8));
    UnqueueMessageOnAckCallback cb = null;
    if (peer.isDarknet() && queueOnNotConnected) {
      int fileNumber = peer.queueN2NM(fs);
      cb = new UnqueueMessageOnAckCallback((DarknetPeerNode) peer, fileNumber);
    }
    try {
      sendAsync(n2nm, cb, peer.node.network().stats().nodeToNodeCounter);
    } catch (NotConnectedException _) {
      if (includeSentTime) {
        fs.removeValue("sentTime");
      }
    }
  }

  /**
   * Accounts for bytes sent during a resend operation.
   *
   * <p>This updates both the transport-local resend counter and the node-wide resend statistics via
   * the shared {@link ByteCounter}. The value is treated as raw bytes and is not validated.
   *
   * @param length number of bytes resent, in raw bytes
   */
  void resendBytes(int length) {
    resendByteCounter.sentBytes(length);
  }

  /**
   * Returns the total resend bytes recorded by this transport.
   *
   * <p>This value is transport-local and updated alongside node-wide resend statistics. It is
   * intended for diagnostics and does not reset.
   *
   * @return cumulative resend bytes sent for this peer transport
   */
  long getResendBytesSent() {
    return resendBytesSent;
  }

  /**
   * Callback used by {@link #sendSync(Message, ByteCounter, boolean)} to track send completion.
   *
   * <p>The instance is stateful and guarded by {@code synchronized} blocks. The callback waits for
   * a sending to complete, records disconnection, and exposes a minimal lifecycle for the blocking
   * sending path.
   */
  private class SyncMessageCallback implements AsyncMessageCallback {

    /** True, once the sending path completes or terminates with an error. */
    private boolean done = false;

    /** True if completion occurred due to a disconnect. */
    private boolean disconnected = false;

    /** True once the message has been sent to the socket. */
    private boolean sent = false;

    /**
     * Waits for the sending to complete or for the deadline to elapse.
     *
     * <p>If the callback completes because the connection was lost, this method throws {@link
     * NotConnectedException}. Interrupts are honored by re-interrupting the thread and returning
     * early without changing the callback state.
     *
     * @param maxWaitInterval maximum time to wait in milliseconds
     * @throws NotConnectedException if the peer disconnects before completion
     */
    public synchronized void waitForSend(long maxWaitInterval) throws NotConnectedException {
      long now = System.currentTimeMillis();
      long end = now + maxWaitInterval;
      while ((now = System.currentTimeMillis()) < end) {
        if (done) {
          if (disconnected) throw new NotConnectedException();
          return;
        }
        int waitTime = (int) Math.min(end - now, Integer.MAX_VALUE);
        try {
          wait(waitTime);
        } catch (InterruptedException _) {
          // Re-interrupt the current thread and stop waiting
          Thread.currentThread().interrupt();
          return;
        }
      }
    }

    @Override
    public void acknowledged() {
      synchronized (this) {
        if (!done) {
          if (!sent) {
            // Can happen due to lag.
            LOG.info(
                "Acknowledged but not sent?! on {}" + STR_FOR + "{} - lag ???",
                this,
                peer.selfPeerNode());
          }
        } else return;
        done = true;
        notifyAll();
      }
    }

    @Override
    public void disconnected() {
      synchronized (this) {
        done = true;
        disconnected = true;
        notifyAll();
      }
    }

    @Override
    public void fatalError() {
      synchronized (this) {
        done = true;
        notifyAll();
      }
    }

    @Override
    public void sent() {
      // It might have been lost, we wait until it is acked.
      synchronized (this) {
        sent = true;
      }
    }
  }

  /**
   * Groups decoded messages for ordered handling after a packet batch is processed.
   *
   * <p>Peer-load status messages are dispatched immediately, while load-limited requests are
   * deferred until the {@link #complete()} phase so other messages can be handled first. This
   * ordering keeps load-control messages responsive without starving normal traffic.
   */
  private final class DecodingMessageGroupImpl implements DecodingMessageGroup {

    /** Messages that can be handled immediately in the completion phase. */
    private final ArrayList<Message> messages;

    /** Messages that are load-limited and processed after normal messages. */
    private final ArrayList<Message> messagesWantSomething;

    /**
     * Creates a group with storage sized for the expected message count.
     *
     * @param size expected number of decoded messages for this batch
     */
    private DecodingMessageGroupImpl(int size) {
      messages = new ArrayList<>(size);
      messagesWantSomething = new ArrayList<>(size);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Messages are decoded using the node's {@link network.crypta.io.comm.MessageCore}. Load
     * status messages are handled immediately; load-limited requests are queued for later.
     */
    @Override
    public void processDecryptedMessage(byte[] data, int offset, int length, int overhead) {
      Message m =
          peer.node.network().usm().decodeSingleMessage(data, offset, length, peer, overhead);
      if (m == null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Message not decoded from {} ({})", peer, peer.getBuildNumber());
        return;
      }
      if (DMT.isPeerLoadStatusMessage(m)) {
        handleMessage(m);
        return;
      }
      if (DMT.isLoadLimitedRequest(m)) {
        messagesWantSomething.add(m);
      } else {
        messages.add(m);
      }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Normal messages are handled first, followed by load-limited requests to preserve
     * responsiveness for non-load-controlled traffic.
     */
    @Override
    public void complete() {
      for (Message msg : messages) {
        handleMessage(msg);
      }
      for (Message msg : messagesWantSomething) {
        handleMessage(msg);
      }
    }
  }
}
