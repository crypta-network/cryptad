package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.SocketHandler;
import network.crypta.io.xfer.PacketThrottle;

/**
 * Transport/messaging operations for a peer connection.
 *
 * <p>This isolates message send/receive behavior and transport primitives from the larger peer
 * implementation. Callers should access messaging via {@link PeerContext#transport()}.
 */
public interface PeerTransport {

  /**
   * Enqueues a message for asynchronous transmission.
   *
   * @param msg message to send
   * @param cb optional callback invoked on send lifecycle events
   * @param ctr byte counter for bandwidth accounting
   * @return handle for the queued message
   * @throws NotConnectedException if the peer is not currently connected
   */
  MessageItem sendAsync(Message msg, AsyncMessageCallback cb, ByteCounter ctr)
      throws NotConnectedException;

  /**
   * Sends a message and waits for acknowledgement or timeout.
   *
   * @param req message to send
   * @param ctr byte counter for bandwidth accounting
   * @param realTime whether the send is real-time
   * @throws NotConnectedException if the peer disconnects before the send completes
   * @throws SyncSendWaitedTooLongException if the acknowledgement does not arrive in time
   */
  void sendSync(Message req, ByteCounter ctr, boolean realTime)
      throws NotConnectedException, SyncSendWaitedTooLongException;

  /**
   * Sends a low-level ping and waits for a pong.
   *
   * @param pingID sequence identifier echoed by the pong
   * @return {@code true} if a reply arrives within 2,000 ms; {@code false} otherwise
   * @throws NotConnectedException if the connection drops while waiting
   */
  boolean ping(int pingID) throws NotConnectedException;

  /**
   * Returns the packet-level throttle for this peer.
   *
   * @return the throttle, or {@code null} if not available
   */
  PacketThrottle getThrottle();

  /**
   * Returns the socket handler backing this peer's transport.
   *
   * @return the socket handler, or {@code null} if none is configured
   */
  SocketHandler getSocketHandler();

  /**
   * Handles a decoded message destined for higher layers.
   *
   * @param msg decoded message
   */
  void handleMessage(Message msg);

  /**
   * Creates a batch handler for decrypted message frames in a single packet.
   *
   * @param count expected number of messages
   * @return a decoding group for the packet
   */
  DecodingMessageGroup startProcessingDecryptedMessages(int count);
}
