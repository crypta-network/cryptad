package network.crypta.io.comm;

import java.lang.ref.WeakReference;
import network.crypta.io.xfer.PacketThrottle;
import network.crypta.node.MessageItem;
import network.crypta.node.OutgoingPacketMangler;
import network.crypta.node.PeerTransport;

/**
 * Lightweight view of a peer connection used by the messaging and transfer layers.
 *
 * <p>Implementations (for example, {@code PeerNode}) expose the minimal contract required to send
 * messages, query connection state, and access throttling/transport primitives without leaking
 * implementation details. Callers typically obtain a {@link PeerContext} from decoded messages or
 * higher-level connection managers.
 *
 * <p>Threading: Methods may be invoked from I/O and worker threads. Implementations should document
 * their own thread-safety characteristics.
 *
 * @author amphibian
 */
public interface PeerContext extends MessageSource {
  // Largely opaque interface for now.

  /**
   * Requests that the underlying connection be closed.
   *
   * <p>Pending operations may fail or be canceled; later calls to {@link #isConnected()} generally
   * return {@code false}.
   */
  void forceDisconnect();

  /**
   * Returns whether a session link to the peer is currently established.
   *
   * @return {@code true} if the session is up and authenticated; {@code false} otherwise.
   */
  boolean isConnected();

  /**
   * Returns whether requests may be routed to this peer at the moment.
   *
   * <p>Implementations may require additional conditions beyond {@link #isConnected()} (for
   * example, routing enabled, backoffs cleared, or policy checks).
   *
   * @return {@code true} if the peer is eligible as a routing target; {@code false} otherwise.
   */
  boolean isRoutable();

  /**
   * Returns the peer's build number if known.
   *
   * @return a non-negative build number, or {@code -1} when unavailable.
   */
  int getBuildNumber();

  /**
   * Returns the transport/messaging component for this peer.
   *
   * <p>Prefer routing message send/receive operations through this component (for example, {@code
   * ctx.transport().sendAsync(...)}).
   *
   * @return the transport component for this peer
   */
  PeerTransport transport();

  /**
   * Enqueues a message for asynchronous transmission to the peer.
   *
   * <p>The call does not block for I/O. The returned {@link MessageItem} can be used to track or
   * cancel the sending. If provided, {@link AsyncMessageCallback} is invoked as delivery
   * progresses. Implementations should account bytes via {@link ByteCounter} where appropriate.
   *
   * @param msg the message to send; must be constructed for this sending path (not reused from a
   *     different source).
   * @param cb optional callback invoked on sending events; may be {@code null}.
   * @param ctr byte counter to update for statistics and throttling; may be {@code null} if the
   *     caller does not wish to record counts.
   * @return a handle representing the queued message.
   * @throws NotConnectedException if no active connection exists.
   */
  default MessageItem sendAsync(Message msg, AsyncMessageCallback cb, ByteCounter ctr)
      throws NotConnectedException {
    return transport().sendAsync(msg, cb, ctr);
  }

  /**
   * Returns the packet-level throttle for the peer's current address.
   *
   * <p>The throttle controls link-level congestion (window size, pacing) for the standard packet
   * size. Implementations may create a new throttle when the remote address changes.
   *
   * @return the throttle, or {@code null} if not available (for example, in tests).
   */
  default PacketThrottle getThrottle() {
    return transport().getThrottle();
  }

  /** Returns the transport handler that receives packets from this peer. */
  @SuppressWarnings("unused")
  default SocketHandler getSocketHandler() {
    return transport().getSocketHandler();
  }

  /** Returns the encoder that encrypts and formats outgoing packets for this peer. */
  OutgoingPacketMangler getOutgoingMangler();

  /**
   * Returns a {@link WeakReference} to this context.
   *
   * <p>Implementations are encouraged to reuse a single weak reference per instance to avoid
   * allocation overhead.
   */
  @Override
  WeakReference<PeerContext> getWeakRef();

  /** Returns a compact, log-friendly description of this peer. */
  String shortToString();

  /**
   * Reports a transfer failure for adaptive backoff and diagnostics.
   *
   * @param reason short description used for logging and metrics.
   * @param realTime {@code true} for the real-time path; {@code false} for bulk.
   */
  void transferFailed(String reason, boolean realTime);

  /**
   * Removes a previously queued message if it has not been sent yet.
   *
   * @param item the queued message handle.
   * @return {@code true} if the item was found and removed; {@code false} otherwise.
   */
  boolean unqueueMessage(MessageItem item);

  /**
   * Reports the time spent waiting for a sending slot due to throttling.
   *
   * @param time elapsed time in milliseconds.
   * @param realTime {@code true} for the real-time path; {@code false} for bulk.
   */
  @SuppressWarnings("unused")
  void reportThrottledPacketSendTime(long time, boolean realTime);

  /**
   * Returns the current link-layer window size in packets.
   *
   * <p>Callers use this as a batching hint when deciding how many chunks to send in one cycle.
   *
   * @return maximum number of packets to keep in flight.
   */
  default int getThrottleWindowSize() {
    PacketThrottle throttle = transport().getThrottle();
    if (throttle != null) {
      return (int) Math.min(throttle.getWindowSize(), Integer.MAX_VALUE);
    }
    return Integer.MAX_VALUE;
  }
}
