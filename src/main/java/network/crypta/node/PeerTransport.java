package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.SocketHandler;
import network.crypta.io.xfer.PacketThrottle;

/**
 * Transport and messaging operations for a single peer connection.
 *
 * <p>This interface isolates message send/receive behavior and transport primitives from the
 * higher-level peer implementation. Callers obtain an instance via {@link PeerContext#transport()}
 * and use it as the single entry point for outbound sends, synchronous sends with acknowledgement
 * waiting, and inbound delivery after decoding. Implementations are typically stateful and bound to
 * the lifecycle of a specific connection; callers should treat the instance as invalid once the
 * peer disconnects and avoid retaining it beyond the connection scope.
 *
 * <p>Concurrency behavior depends on the implementation. Callers should assume methods may be
 * invoked from network I/O threads or scheduler threads and therefore should avoid holding
 * long-lived locks while interacting with the transport. Implementations are expected to apply any
 * necessary serialization, throttling, or backpressure internally.
 *
 * <ul>
 *   <li>Queue asynchronous outbound messages and provide lifecycle callbacks.
 *   <li>Block for synchronous acknowledgement with bounded waiting.
 *   <li>Expose low-level transport components such as throttles and socket handlers.
 *   <li>Route decoded messages and create per-packet decoding groups.
 * </ul>
 *
 * @see PeerContext#transport()
 * @see SocketHandler
 */
public interface PeerTransport {

  /**
   * Enqueues a message for asynchronous transmission over the connection.
   *
   * <p>The call schedules the message for outbound delivery and returns immediately. The transport
   * controls when the message is serialized and written to the socket based on its internal
   * buffering and throttling. If provided, the callback is invoked for lifecycle events such as
   * queued, sent, or failed. The byte counter is used to account for payload bytes as they are
   * transmitted. The call is not idempotent; invoking it multiple times enqueues multiple copies.
   *
   * <pre>{@code
   * MessageItem item = transport.sendAsync(message, callback, counter);
   * }</pre>
   *
   * @param msg message to send; must be a fully populated, encodable instance
   * @param cb optional callback for send lifecycle events; may be {@code null}
   * @param ctr byte counter used for bandwidth accounting; may be {@code null}
   * @return a handle representing the queued message and its delivery state
   * @throws NotConnectedException if the peer is not currently connected
   */
  MessageItem sendAsync(Message msg, AsyncMessageCallback cb, ByteCounter ctr)
      throws NotConnectedException;

  /**
   * Sends a message synchronously and waits for acknowledgement or timeout.
   *
   * <p>This call blocks the caller thread until an acknowledgement arrives or a timeout condition
   * is reached by the implementation. It is primarily intended for control messages that require a
   * bounded acknowledgement path. The {@code realTime} flag informs the transport about scheduling
   * preference; implementations may prioritize the message or use different throttling behavior.
   * The call is not idempotent and should not be retried without higher-level coordination.
   *
   * <pre>{@code
   * transport.sendSync(request, counter, true);
   * }</pre>
   *
   * @param req message to send; must be a fully populated, encodable instance
   * @param ctr byte counter used for bandwidth accounting; may be {@code null}
   * @param realTime {@code true} to request real-time scheduling; {@code false} otherwise
   * @throws NotConnectedException if the peer disconnects before the send completes
   * @throws SyncSendWaitedTooLongException if the acknowledgement does not arrive in time
   */
  void sendSync(Message req, ByteCounter ctr, boolean realTime)
      throws NotConnectedException, SyncSendWaitedTooLongException;

  /**
   * Sends a message synchronously using explicit timeout bounds.
   *
   * <p>Implementations may override this to provide tuned timeouts for specific call sites while
   * preserving the same synchronous semantics as {@link #sendSync(Message, ByteCounter, boolean)}.
   * The default implementation delegates to the legacy method and ignores the timeout parameters to
   * keep backward compatibility for transports that do not need custom bounds.
   *
   * @param req message to send; must be a fully populated, encodable instance
   * @param ctr byte counter used for bandwidth accounting; may be {@code null}
   * @param realTime {@code true} to request real-time scheduling; {@code false} otherwise
   * @param sendTimeoutMillis primary wait before trying to un-queue a blocked send
   * @param unqueueWaitMillis additional wait after un-queue failure before giving up
   * @throws NotConnectedException if the peer disconnects before the send completes
   * @throws SyncSendWaitedTooLongException if the acknowledgement does not arrive in time
   */
  default void sendSync(
      Message req,
      ByteCounter ctr,
      boolean realTime,
      long sendTimeoutMillis,
      long unqueueWaitMillis)
      throws NotConnectedException, SyncSendWaitedTooLongException {
    sendSync(req, ctr, realTime);
  }

  /**
   * Sends a low-level ping and waits for a corresponding pong.
   *
   * <p>The call transmits a transport-level ping message and blocks until a reply is received or
   * the implementation-defined timeout elapses. The {@code pingID} is echoed back by the peer and
   * used to correlate the response. Implementations may treat overlapping pings as separate
   * requests and should handle duplicate identifiers according to their internal rules.
   *
   * @param pingID sequence identifier echoed by the pong; used for correlation
   * @return {@code true} if a reply arrives within 2,000 ms; {@code false} otherwise
   * @throws NotConnectedException if the connection drops while waiting
   */
  boolean ping(int pingID) throws NotConnectedException;

  /**
   * Returns the packet-level throttle used by this peer's transport.
   *
   * <p>The throttle governs how quickly packets are emitted on the wire and typically reflects
   * configured bandwidth limits and congestion policies. Callers should treat the throttle as a
   * live, mutable component owned by the transport. If the transport does not expose throttling,
   * the method returns {@code null}.
   *
   * @return the throttle instance, or {@code null} if throttling is not exposed
   */
  PacketThrottle getThrottle();

  /**
   * Returns the socket handler backing this peer's transport.
   *
   * <p>The socket handler provides lower-level access to connection state and I/O coordination.
   * This accessor is primarily used by infrastructure components that need visibility into the
   * underlying socket. Callers must not close or otherwise mutate the handler outside transport
   * ownership. If no handler is configured, the method returns {@code null}.
   *
   * @return the socket handler, or {@code null} if none is configured
   */
  SocketHandler getSocketHandler();

  /**
   * Handles a decoded message destined for higher layers of the peer stack.
   *
   * <p>The transport calls this method after a message has been fully decoded and validated at the
   * framing level. Implementations typically forward the message to peer logic or dispatch it onto
   * an appropriate executor. The call may be invoked on an I/O thread, so implementations should
   * avoid long-running work in the direct call path.
   *
   * @param msg decoded message ready for higher-level handling; must be non-{@code null}
   */
  void handleMessage(Message msg);

  /**
   * Creates a batch handler for decrypted message frames in a single packet.
   *
   * <p>The transport creates a decoding group per packet so that multiple frames can be decoded and
   * delivered as a cohesive unit. The {@code count} parameter indicates the expected number of
   * messages in the packet and is used to size internal buffers. The returned group is consumed by
   * the decoding pipeline, which adds messages in order as they are processed.
   *
   * @param count expected number of messages in the packet; must be non-negative
   * @return a decoding group responsible for aggregating messages from the packet
   */
  DecodingMessageGroup startProcessingDecryptedMessages(int count);
}
