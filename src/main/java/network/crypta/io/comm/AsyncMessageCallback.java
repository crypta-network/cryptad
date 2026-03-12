package network.crypta.io.comm;

/**
 * Receives progress and completion notifications for an asynchronously sent packet/message.
 *
 * <p>The sender uses this callback to report when a packet has been handed off to the transport and
 * when the transmission completes or fails. On a reliable (non-lossy) transport, the peer's
 * acknowledgment may follow immediately after {@link #sent()}; on a lossy transport, only {@link
 * #acknowledged()} confirms reception by the remote node.
 *
 * <p>Implementations should return quickly and avoid long blocking operations; callback methods may
 * be invoked from internal networking or scheduler threads.
 */
public interface AsyncMessageCallback {

  /**
   * Invoked when the packet actually leaves the local node (i.e., handed to the transport or
   * written to the socket/output queue). This does not imply the remote node has received it on a
   * lossy transport.
   */
  void sent();

  /**
   * Invoked when the remote node acknowledges receipt of the packet. This marks the end of the
   * transmission for this packet. On a reliable (non-lossy) transport this may be called
   * immediately after {@link #sent()}.
   */
  void acknowledged();

  /**
   * Invoked if the connection is lost while the packet is queued or after it has been sent.
   * Terminal.
   */
  void disconnected();

  /** Invoked if the packet is lost due to an unrecoverable internal error. Terminal. */
  void fatalError();
}
