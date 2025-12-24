package network.crypta.io.xfer;

import static java.util.concurrent.TimeUnit.SECONDS;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.RetrievalException;
import network.crypta.support.ShortBuffer;

/**
 * Receives a segmented bulk transfer from a single peer and writes packets into a {@link
 * PartiallyReceivedBulk}.
 *
 * <p>This helper drives the receive side of the bulk protocol used for large files. It waits for
 * {@link network.crypta.io.comm.DMT#FNPBulkPacketSend} messages from the configured {@link
 * network.crypta.io.comm.PeerContext}, commits data to the supplied {@link PartiallyReceivedBulk},
 * and acknowledges completion via {@link network.crypta.io.comm.DMT#FNPBulkReceivedAll} when all
 * blocks have been received. It also reacts to sender aborts, timeouts, disconnects, and peer
 * restarts by aborting the {@code PartiallyReceivedBulk} with an appropriate {@link
 * network.crypta.io.comm.RetrievalException} reason.
 *
 * <h2>Lifecycle</h2>
 *
 * <ul>
 *   <li>Construction records the peer's boot id and sets {@code prb.recv = this} for callbacks.
 *   <li>{@link #receive()} blocks in a loop until the transfer completes (returns {@code true}) or
 *       fails (returns {@code false}).
 *   <li>{@link #onAborted()} may be invoked to inform the peer that the receiver cancelled; it is
 *       idempotent and safe to call more than once.
 * </ul>
 *
 * <h2>Threading</h2>
 *
 * <p>Instances are not thread‑safe. Callers must serialize use, typically by invoking {@link
 * #receive()} from a single worker thread. {@link #onAborted()} uses a small synchronized guard so
 * duplicate notifications are suppressed.
 *
 * <h2>Timeouts</h2>
 *
 * <p>Each {@code waitFor(...)} iteration uses a per‑iteration timeout of {@link #TIMEOUT}. The
 * overall wall‑clock time to complete can exceed this value because the method loops until a
 * terminal condition is reached.
 *
 * @author toad
 */
public class BulkReceiver {

  /** Per-iteration wait timeout (milliseconds) used while receiving packets. */
  static final long TIMEOUT = SECONDS.toMillis(60);

  /** Tracks receive progress and persists packet data. */
  final PartiallyReceivedBulk prb;

  /** Peer we expect to receive messages from for this transfer. */
  final PeerContext peer;

  /** Transfer identifier used to filter and send protocol messages. */
  final long uid;

  private boolean sentCancel;

  /** Peer boot id captured at construction; used to detect remote restarts. */
  final long peerBootID;

  private final ByteCounter ctr;

  /**
   * Creates a receiver bound to a target {@link PartiallyReceivedBulk} and peer.
   *
   * @param prb destination that records blocks and abort state; its {@code size} must match the
   *     file being transferred, and its backing buffer must be at least that size.
   * @param peer source peer for all matching messages; its current boot id is recorded to detect
   *     restarts during the transfer.
   * @param uid protocol identifier shared by all transfer messages.
   * @param ctr optional byte counter for accounting; may be {@code null}.
   */
  public BulkReceiver(PartiallyReceivedBulk prb, PeerContext peer, long uid, ByteCounter ctr) {
    this.prb = prb;
    this.peer = peer;
    this.uid = uid;
    this.peerBootID = peer.getBootID();
    this.ctr = ctr;

    prb.recv = this;
  }

  /**
   * Sends a single {@link network.crypta.io.comm.DMT#FNPBulkReceiveAborted} to the peer.
   *
   * <p>Multiple calls are safe; only the first results in a message being sent. A missing
   * connection is ignored because the sender cannot be notified in that state.
   */
  public void onAborted() {
    synchronized (this) {
      if (sentCancel) return;
      sentCancel = true;
    }
    try {
      peer.sendAsync(DMT.createFNPBulkReceiveAborted(uid), null, ctr);
    } catch (NotConnectedException _) {
      // Peer is already disconnected; there is nothing to notify.
    }
  }

  /**
   * Drives the blocking receive loop for this transfer.
   *
   * <p>On each iteration the method waits for either a data packet ({@link
   * network.crypta.io.comm.DMT#FNPBulkPacketSend}) or a sender abort ({@link
   * network.crypta.io.comm.DMT#FNPBulkSendAborted}) from the configured peer with the matching
   * {@link #uid}. Received packet payloads are written to the {@link PartiallyReceivedBulk}. When
   * {@link PartiallyReceivedBulk#hasWholeFile()} becomes {@code true}, the method acknowledges
   * completion by sending {@link network.crypta.io.comm.DMT#FNPBulkReceivedAll} and returns.
   *
   * <p>Failure conditions abort the {@code PartiallyReceivedBulk} and cause the method to return
   * {@code false}. The abort reason is one of:
   *
   * <ul>
   *   <li>{@link network.crypta.io.comm.RetrievalException#SENDER_DISCONNECTED} when waiting fails
   *       due to a disconnect.
   *   <li>{@link network.crypta.io.comm.RetrievalException#SENDER_DIED} when the sender restarts or
   *       cancels the send.
   *   <li>{@link network.crypta.io.comm.RetrievalException#TIMED_OUT} when no relevant message
   *       arrives within {@link #TIMEOUT}.
   * </ul>
   *
   * <p>Blocking: May block repeatedly for up to {@link #TIMEOUT} per iteration until a terminal
   * condition is reached.
   *
   * @return {@code true} if the entire file was received and acknowledged; {@code false} if the
   *     transfer aborted or timed out.
   */
  public boolean receive() {
    while (true) {
      // Build per-iteration filters for either a sender abort or a data packet from this peer.
      MessageFilter mfSendKilled =
          MessageFilter.create()
              .setSource(peer)
              .setType(DMT.FNPBulkSendAborted)
              .setField(DMT.UID, uid)
              .setTimeout(TIMEOUT);
      MessageFilter mfPacket =
          MessageFilter.create()
              .setSource(peer)
              .setType(DMT.FNPBulkPacketSend)
              .setField(DMT.UID, uid)
              .setTimeout(TIMEOUT);
      if (prb.hasWholeFile()) {
        try {
          // Fast-path: data may have arrived concurrently; acknowledge completion immediately.
          peer.sendAsync(DMT.createFNPBulkReceivedAll(uid), null, ctr);
        } catch (NotConnectedException _) {
          // Acknowledge best-effort only. We already have the data locally.
        }
        return true;
      }
      Message m;
      try {
        // Wait for either filter to match; returns null on timeout.
        m = prb.usm.waitFor(mfSendKilled.or(mfPacket), ctr);
      } catch (DisconnectedException _) {
        prb.abort(RetrievalException.SENDER_DISCONNECTED, "Sender disconnected");
        return false;
      }
      if (peer.getBootID() != peerBootID) {
        // Remote peer restarted during the transfer; treat as sender death.
        prb.abort(RetrievalException.SENDER_DIED, "Sender restarted");
        return false;
      }
      if (m == null) {
        // Neither packet nor abort arrived within TIMEOUT.
        prb.abort(RetrievalException.TIMED_OUT, "Sender timeout");
        return false;
      }
      if (m.getSpec() == DMT.FNPBulkSendAborted) {
        // Sender explicitly cancelled this transfer.
        prb.abort(RetrievalException.SENDER_DIED, "Sender cancelled send");
        return false;
      }
      if (m.getSpec() == DMT.FNPBulkPacketSend) {
        int packetNo = m.getInt(DMT.PACKET_NO);
        byte[] data = ((ShortBuffer) m.getObject(DMT.DATA)).getData();
        // Commit the packet payload to storage. Length is validated by PartiallyReceivedBulk.
        prb.received(packetNo, data, 0, data.length);
      }
    }
  }
}
