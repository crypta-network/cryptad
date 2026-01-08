package network.crypta.node;

import java.util.Arrays;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.RetrievalException;
import network.crypta.io.comm.SlowAsyncMessageFilterCallback;
import network.crypta.io.xfer.BulkReceiver;
import network.crypta.io.xfer.PartiallyReceivedBulk;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Waits for and receives opennet noderefs, including the bulk transfer step.
 *
 * <p>This helper concentrates the opennet noderef receive flow so callers can initiate a wait and
 * obtain either a noderef payload, a completion acknowledgment, or a timeout outcome. It installs
 * message filters for noderef-delivery messages and completion acks, then drives the bulk transfer
 * using the transfer UID embedded in the matched message. Callers typically use the synchronous
 * wrapper for simple workflows or the callback-based form when integrating with existing
 * asynchronous control flow.
 *
 * <p>State is short-lived and tied to the message filter lifecycle: once any terminal condition is
 * observed, the callback is completed exactly once and no further work is performed. The helper
 * does not retain data beyond the call boundaries, and it does not modify peer state beyond
 * optional rejection signaling on failed transfers.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> register filters, handle acks/timeouts, and copy the
 *       noderef payload from the bulk receiver.
 *   <li><strong>Notable behaviors:</strong> returns {@code null} on disconnect or failed receive
 *       and throws only for explicit wait timeouts.
 * </ul>
 *
 * @see OpennetManager
 * @see RequestSender#OPENNET_TIMEOUT
 */
final class OpennetNoderefWaiter {

  private static final Logger LOG = LoggerFactory.getLogger(OpennetNoderefWaiter.class);

  private OpennetNoderefWaiter() {}

  /**
   * Carries immutable context needed to complete an opennet noderef transfer.
   *
   * <p>This record groups together the peer, node, and accounting information needed by the bulk
   * receiver so the inner transfer logic can remain focused on data movement and error handling.
   * Instances are thread-safe by virtue of immutability and are intended to be short-lived.
   *
   * @param source peer that will send or has sent the noderef payload
   * @param isReply {@code true} when waiting for a reply message, {@code false} otherwise
   * @param uid parent request UID used for correlation and logging
   * @param sendReject whether to emit a rejection on transfer failure
   * @param ctr byte counter for accounting payload and overhead bytes
   * @param node owning node that provides access to messaging subsystems
   */
  record NoderefTransferCtx(
      PeerNode source, boolean isReply, long uid, boolean sendReject, ByteCounter ctr, Node node) {}

  /**
   * Callback interface for noderef receipt, acknowledgments, and timeouts.
   *
   * <p>Implementations must be prepared for exactly one terminal callback per wait request. The
   * {@code gotNoderef} callback may receive {@code null} when the peer disconnects or when transfer
   * completion is acknowledged without a noderef payload.
   */
  interface NoderefCallback {
    /**
     * Reports that a noderef payload was received or that no payload is available.
     *
     * <p>The provided buffer is owned by the caller and will not be reused. A {@code null} value
     * indicates a disconnect or other non-timeout failure that ends the wait.
     *
     * @param noderef noderef bytes, or {@code null} when no payload is available
     */
    void gotNoderef(byte[] noderef);

    /**
     * Reports that the wait timed out before receiving any terminal response.
     *
     * <p>Callers should treat this as a distinct outcome from {@link #acked(boolean)}, since it
     * indicates local timeout rather than a remote completion signal.
     */
    void timedOut();

    /**
     * Reports that the peer sent a completion acknowledgment without a noderef payload.
     *
     * <p>This indicates the wait completed without local timeout; the remote side has explicitly
     * signaled completion and no payload will arrive for this UID.
     *
     * @param timedOutMessage {@code true} when the upstream reports a timeout, {@code false} for a
     *     regular completion ack from the peer
     */
    void acked(boolean timedOutMessage);
  }

  private static class SyncNoderefCallback implements NoderefCallback {

    byte[] returned;
    boolean finished;
    boolean timedOut;

    @Override
    public synchronized void timedOut() {
      timedOut = true;
      finished = true;
      notifyAll();
    }

    @Override
    public void acked(boolean timedOutMessage) {
      gotNoderef(null);
    }

    @Override
    public synchronized void gotNoderef(byte[] noderef) {
      returned = noderef;
      finished = true;
      notifyAll();
    }

    public synchronized byte[] waitForResult() throws WaitedTooLongForOpennetNoderefException {
      while (!finished)
        try {
          wait();
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
        }
      if (timedOut) throw new WaitedTooLongForOpennetNoderefException();
      return returned;
    }
  }

  /**
   * Signals that a synchronous wait exceeded its timeout without receiving a terminal response.
   *
   * <p>This exception is thrown only by {@link #waitForOpennetNoderef(boolean, PeerNode, long,
   * ByteCounter, Node)} when the wait timer expires locally. It is not used for remote acks,
   * disconnects, or transfer failures, which instead return {@code null}.
   */
  static class WaitedTooLongForOpennetNoderefException extends Exception {}

  /**
   * Waits synchronously for an opennet noderef or completion signal.
   *
   * <p>This method blocks the calling thread until a noderef is received, a completion ack arrives,
   * or the wait times out. On success, it returns a newly allocated byte array containing the
   * noderef payload. If the peer disconnects or sends a completion ack without payload, the method
   * returns {@code null}. It is safe to call repeatedly for different UIDs; each call installs its
   * own filter and does not share state with other waits.
   *
   * <pre>{@code
   * byte[] noderef = OpennetNoderefWaiter.waitForOpennetNoderef(
   *     true, peer, uid, ctr, node);
   * }</pre>
   *
   * @param isReply {@code true} to expect a reply message, {@code false} for destination messages
   * @param source peer expected to send the noderef or completion signal
   * @param uid parent request UID used to correlate messages and transfers
   * @param ctr byte counter used for accounting; may be {@code null}
   * @param node owning node that provides the messaging subsystem
   * @return noderef bytes, or {@code null} if no payload is available
   * @throws WaitedTooLongForOpennetNoderefException if the local wait times out
   */
  static byte[] waitForOpennetNoderef(
      boolean isReply, PeerNode source, long uid, ByteCounter ctr, Node node)
      throws WaitedTooLongForOpennetNoderefException {
    SyncNoderefCallback cb = new SyncNoderefCallback();
    if (LOG.isDebugEnabled())
      LOG.debug("Wait for opennet noderef uid={} from {} reply={}", uid, source, isReply);
    waitForOpennetNoderef(isReply, source, uid, ctr, cb, node);
    return cb.waitForResult();
  }

  /**
   * Waits asynchronously for an opennet noderef or completion ack and reports to a callback.
   *
   * <p>The method installs message filters for noderef delivery and completion acknowledgments and
   * returns immediately. The provided {@link NoderefCallback} is invoked exactly once with either a
   * payload, an ack, or a timeout. On disconnect or restart events, the callback receives {@code
   * null} via {@link NoderefCallback#gotNoderef(byte[])}.
   *
   * <p>Timeout behavior is governed by {@link RequestSender#OPENNET_TIMEOUT}; the callback's {@link
   * NoderefCallback#timedOut()} method is invoked only for local timeouts, not for remote
   * completion acks.
   *
   * @param isReply {@code true} to expect {@link DMT#FNPOpennetConnectReplyNew} messages
   * @param source source peer that will send the noderef or completion ack
   * @param uid parent request UID used to correlate messages and transfers
   * @param ctr byte counter used for accounting; may be {@code null}
   * @param callback callback invoked on noderef receipt, ack, or timeout
   * @param node owning node used to register message filters
   */
  static void waitForOpennetNoderef(
      final boolean isReply,
      final PeerNode source,
      final long uid,
      final ByteCounter ctr,
      final NoderefCallback callback,
      final Node node) {
    // Backward-compatibility handling
    MessageFilter mf =
        MessageFilter.create()
            .setSource(source)
            .setField(DMT.UID, uid)
            .setTimeout(RequestSender.OPENNET_TIMEOUT)
            .setType(isReply ? DMT.FNPOpennetConnectReplyNew : DMT.FNPOpennetConnectDestinationNew);
    // Also waiting for an ack
    MessageFilter mfAck =
        MessageFilter.create()
            .setSource(source)
            .setField(DMT.UID, uid)
            .setTimeout(RequestSender.OPENNET_TIMEOUT)
            .setType(DMT.FNPOpennetCompletedAck);
    // Also waiting for an upstream timed out.
    MessageFilter mfAckTimeout =
        MessageFilter.create()
            .setSource(source)
            .setField(DMT.UID, uid)
            .setTimeout(RequestSender.OPENNET_TIMEOUT)
            .setType(DMT.FNPOpennetCompletedTimeout);

    mf = mfAck.or(mfAckTimeout.or(mf));
    try {
      node.network()
          .usm()
          .addAsyncFilter(
              mf,
              new SlowAsyncMessageFilterCallback() {

                boolean completed;

                @Override
                public void onMatched(Message msg) {
                  if (msg.getSpec() == DMT.FNPOpennetCompletedAck
                      || msg.getSpec() == DMT.FNPOpennetCompletedTimeout) {
                    synchronized (this) {
                      if (completed) return;
                      completed = true;
                    }
                    callback.acked(msg.getSpec() == DMT.FNPOpennetCompletedTimeout);
                  } else {
                    // Noderef bulk transfer
                    long xferUID = msg.getLong(DMT.TRANSFER_UID);
                    int paddedLength = msg.getInt(DMT.PADDED_LENGTH);
                    int realLength = msg.getInt(DMT.NODEREF_LENGTH);
                    complete(
                        innerWaitForOpennetNoderef(
                            xferUID,
                            paddedLength,
                            realLength,
                            new NoderefTransferCtx(source, isReply, uid, false, ctr, node)));
                  }
                }

                @Override
                public boolean shouldTimeout() {
                  return false;
                }

                @Override
                public void onTimeout() {
                  synchronized (this) {
                    if (completed) return;
                    completed = true;
                  }
                  callback.timedOut();
                }

                @Override
                public void onDisconnect(PeerContext ctx) {
                  complete(null);
                }

                @Override
                public void onRestarted(PeerContext ctx) {
                  complete(null);
                }

                @Override
                public int getPriority() {
                  return Thread.NORM_PRIORITY;
                }

                private void complete(byte[] buf) {
                  synchronized (this) {
                    if (completed) return;
                    completed = true;
                  }
                  callback.gotNoderef(buf);
                }
              },
              ctr);
    } catch (DisconnectedException _) {
      callback.gotNoderef(null);
    }
  }

  /**
   * Completes a bulk noderef transfer and returns the received payload.
   *
   * <p>This method allocates a padded buffer sized to the transfer, receives the data via {@link
   * BulkReceiver}, and returns a trimmed copy containing only the unpadded noderef bytes. When the
   * transfer fails, it logs the failure reason, optionally sends a rejection to the peer, and
   * returns {@code null}. The method is deterministic with respect to the provided context and does
   * not mutate global state beyond optional reject signaling and logging.
   *
   * <p>Callers must ensure {@code realLength} is less than or equal to {@code paddedLength}. The
   * returned array is a fresh copy and is safe for the caller to retain or modify.
   *
   * @param xferUID transfer UID used to match bulk packets from the peer
   * @param paddedLength total transfer length in bytes, including padding
   * @param realLength actual noderef length in bytes, excluding padding
   * @param ctx immutable context describing the peer, node, and accounting details
   * @return trimmed noderef bytes, or {@code null} when the transfer fails
   */
  @SuppressWarnings("java:S1168")
  static byte[] innerWaitForOpennetNoderef(
      long xferUID, int paddedLength, int realLength, NoderefTransferCtx ctx) {
    byte[] buf = new byte[paddedLength];
    ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(buf);
    PartiallyReceivedBulk prb =
        new PartiallyReceivedBulk(
            ctx.node.network().usm(), buf.length, Node.PACKET_SIZE, raf, false);
    BulkReceiver br = new BulkReceiver(prb, ctx.source, xferUID, ctx.ctr);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Receive opennet noderef (reply={}) via bulk transfer (uid={} xferUID={} from={})",
          ctx.isReply,
          ctx.uid,
          xferUID,
          ctx.source);
    }
    if (!br.receive()) {
      if (ctx.source.isConnected()) {
        String msg =
            "Failed to receive noderef bulk transfer : "
                + RetrievalException.getErrString(prb.getAbortReason())
                + " : "
                + prb.getAbortDescription()
                + " from "
                + ctx.source;
        if (prb.getAbortReason() != RetrievalException.SENDER_DISCONNECTED) {
          LOG.warn(msg);
        } else {
          LOG.info(msg);
        }
        if (ctx.sendReject)
          OpennetManager.rejectRef(
              ctx.uid, ctx.source, DMT.NODEREF_REJECTED_TRANSFER_FAILED, ctx.ctr);
      }
      return null;
    }
    return Arrays.copyOf(buf, realLength);
  }
}
