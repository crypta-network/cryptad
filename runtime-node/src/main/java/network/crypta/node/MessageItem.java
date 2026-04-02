package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Queued outbound payload with optional {@link Message} and callbacks.
 *
 * <p>This item holds the encoded bytes that will be sent on the wire. The buffer is created during
 * construction so callers can obtain the exact length immediately. When {@link #formatted} is
 * {@code true}, the buffer may contain multiple messages already framed as one packet.
 *
 * <p>Resilience: byte counting and callback notifications are deliberately isolated from the core
 * networking flow. Implementations of {@link AsyncMessageCallback} and {@link ByteCounter} are
 * allowed to throw; we catch and log {@link Throwable} around those invocations to ensure a
 * misbehaving observer cannot break send, disconnect, or accounting paths.
 */
public final class MessageItem {
  private static final Logger LOG = LoggerFactory.getLogger(MessageItem.class);

  final Message msg;
  final byte[] buf;
  final AsyncMessageCallback[] cb;
  final long submitted;

  /**
   * When {@code true}, {@link #buf} may contain multiple messages and is preformatted as a single
   * packet for immediate transmission.
   */
  final boolean formatted;

  final ByteCounter ctrCallback;
  private final short priority;
  private long cachedID;
  private boolean hasCachedID;
  private long deadline;

  public MessageItem(
      Message msg2, AsyncMessageCallback[] cb2, ByteCounter ctr, short overridePriority) {
    this.msg = msg2;
    this.cb = cb2;
    formatted = false;
    this.ctrCallback = ctr;
    this.submitted = System.currentTimeMillis();
    if (overridePriority > 0) priority = overridePriority;
    else priority = msg2.getPriority();
    buf = msg.encodeToPacket();
    if (buf.length > NewPacketFormat.MAX_MESSAGE_SIZE) {
      /*
       * Fairness is enforced at message queueing. Very large frames can monopolize a small
       * send window and starve other UIDs, which in turn increases timeout risk (especially
       * under retransmission).
       */
      LOG.warn("Encoded message size {} bytes exceeds limit for {}", buf.length, msg2);
    }
  }

  public MessageItem(Message msg2, AsyncMessageCallback[] cb2, ByteCounter ctr) {
    this(msg2, cb2, ctr, (short) -1);
  }

  public MessageItem(
      byte[] data, AsyncMessageCallback[] cb2, boolean formatted, ByteCounter ctr, short priority) {
    this.cb = cb2;
    this.msg = null;
    this.buf = data;
    this.formatted = formatted;
    if (formatted && buf == null) throw new NullPointerException();
    this.ctrCallback = ctr;
    this.submitted = System.currentTimeMillis();
    this.priority = priority;
  }

  /**
   * Returns the encoded payload.
   *
   * <p>When {@link #formatted} is {@code true}, the buffer may carry multiple messages arranged as
   * one packet. The returned array is the internal backing buffer and must not be modified by
   * callers.
   *
   * @return byte array containing the on‑wire representation; never {@code null}
   */
  public byte[] getData() {
    return buf;
  }

  /**
   * Returns the number of bytes in {@link #getData()}.
   *
   * @return payload length in bytes
   */
  public int getLength() {
    return buf.length;
  }

  /**
   * Records the number of bytes sent for throttle accounting.
   *
   * @param length The actual number of bytes sent to send this message, including our share of the
   *     packet overheads, *and including alreadyReportedBytes*, which is only used when deciding
   *     how many bytes to report to the throttle.
   */
  @SuppressWarnings("java:S1181")
  public void onSent(int length) {
    // Count bytes before invoking callbacks to keep load accounting consistent.
    if (ctrCallback != null) {
      try {
        ctrCallback.sentBytes(length);
      } catch (Throwable t) {
        // Callbacks/instrumentation must never break the send flow.
        LOG.error("sentBytes callback threw; bytes={} item={}", length, this, t);
      }
    }
  }

  public short getPriority() {
    return priority;
  }

  @Override
  public String toString() {
    return super.toString() + ":formatted=" + formatted + ",msg=" + msg;
  }

  /**
   * Notifies callbacks that the connection closed before delivery completed.
   *
   * <p>Exceptions from callbacks are caught and logged to preserve the disconnect loop.
   */
  @SuppressWarnings("java:S1181")
  public void onDisconnect() {
    if (cb != null) {
      for (AsyncMessageCallback cbi : cb) {
        try {
          cbi.disconnected();
        } catch (Throwable t) {
          // Keep the disconnect loop resilient if callbacks misbehave.
          LOG.error("disconnected() callback threw on {} for {}", cbi, this, t);
        }
      }
    }
  }

  /** Notifies callbacks that a fatal error occurred and the item cannot be delivered. */
  @SuppressWarnings("java:S1181")
  public void onFailed() {
    if (cb != null) {
      for (AsyncMessageCallback cbi : cb) {
        try {
          cbi.fatalError();
        } catch (Throwable t) {
          LOG.error("fatalError() callback threw on {} for {}", cbi, this, t);
        }
      }
    }
  }

  /**
   * Returns a stable identifier for logging/fairness derived from {@link DMT#UID}.
   *
   * <p>The value is computed once and cached. When this item wraps a raw buffer ({@link #msg} is
   * {@code null}) or when the underlying message lacks a UID, {@code -1} is returned.
   *
   * <p>Thread‑safety: synchronized to ensure a single computation and visibility of the cached
   * value.
   *
   * @return UID as a {@code long}, or {@code -1} when unavailable
   */
  public synchronized long getID() {
    if (hasCachedID) return cachedID;
    cachedID = generateID();
    hasCachedID = true;
    return cachedID;
  }

  private long generateID() {
    if (msg == null) return -1;
    Object o = msg.getObject(DMT.UID);
    if (o instanceof Long id) {
      return id;
    } else {
      return -1;
    }
  }

  /**
   * Invoked the first time the full payload has been transmitted.
   *
   * <p>Subsequent retransmissions do not trigger another call. Exceptions from callbacks are caught
   * and logged.
   */
  @SuppressWarnings("java:S1181")
  public void onSentAll() {
    if (cb != null) {
      for (AsyncMessageCallback cbi : cb) {
        try {
          cbi.sent();
        } catch (Throwable t) {
          LOG.error("sent() callback threw on {} for {}", cbi, this, t);
        }
      }
    }
  }

  /**
   * Set the deadline for this message. Called when a message is unqueued, when we start to send it.
   * Used if the message does not entirely fit in the packet, and also if it is retransmitted.
   *
   * <p>Thread‑safety: synchronized.
   *
   * @param time absolute time in milliseconds since epoch at which this item expires
   */
  public synchronized void setDeadline(long time) {
    deadline = time;
  }

  /**
   * Clears any previously set deadline.
   *
   * <p>Thread‑safety: synchronized.
   */
  public synchronized void clearDeadline() {
    deadline = 0;
  }

  /**
   * Returns the current deadline.
   *
   * @return absolute time in milliseconds since epoch, or {@code 0} when no deadline is set
   */
  public synchronized long getDeadline() {
    return deadline;
  }
}
