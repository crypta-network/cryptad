package network.crypta.node;

import java.util.List;
import network.crypta.io.comm.Peer;

/**
 * Packet formatting and scheduling contract for peer transports.
 *
 * <p>Implementations encapsulate send/receive state, fragment assembly, acknowledgment handling,
 * retransmission checks, and scheduling hints consumed by higher-level components such as {@link
 * PacketSender}. Time values are in milliseconds unless stated otherwise.
 */
public interface PacketFormat {

  /**
   * Processes a received packet.
   *
   * <p>The implementation attempts to decrypt, validate, and parse the packet, apply any
   * acknowledgments, and deliver completed messages to the owning peer. When applicable, it may
   * schedule an acknowledgment in response.
   *
   * @param buf buffer containing the packet bytes
   * @param offset start offset in {@code buf}
   * @param length number of bytes to read from {@code buf}
   * @param now current time in milliseconds (epoch)
   * @param replyTo peer that sent the packet; may be {@code null} for non-addressable transports
   * @return {@code true} if the packet was accepted and processed; {@code false} if it did not
   *     match any active session or failed validation
   */
  boolean handleReceivedPacket(byte[] buf, int offset, int length, long now, Peer replyTo);

  /**
   * Attempts to send at most one packet.
   *
   * <p>Sending a single packet promotes fairness across peers and prevents long blocking on large
   * queues. The caller typically invokes this in a round‑robin loop.
   *
   * @param now current time in milliseconds (epoch)
   * @param ackOnly when {@code true}, restricts the packet to acknowledgments/keepalives
   * @return {@code true} if a packet was sent; {@code false} if nothing was emitted
   * @throws BlockedTooLongException if internal constraints (for example, sequence allocation) are
   *     blocked beyond the allowed threshold
   */
  boolean maybeSendPacket(long now, boolean ackOnly) throws BlockedTooLongException;

  /**
   * Notifies the formatter that the peer disconnected and returns any queued items to requeue.
   *
   * <p>After this method returns, the instance is considered terminated and must not be used by the
   * caller.
   *
   * @return outstanding {@link MessageItem}s that were not fully sent; may be empty
   */
  List<MessageItem> onDisconnect();

  /**
   * Returns whether a new data packet can be created now using the given session key.
   *
   * <p>This governs packets built from messages queued in {@link PeerMessageQueue}. It may return
   * {@code false} when the implementation must wait for an internal event (for example, sequence
   * number allocation). There may already be packets in flight; consult {@link
   * #timeNextUrgent(boolean, long)} for the next required action time.
   *
   * @param key session key on which the packet would be sent
   * @return {@code true} if a new data packet can be constructed; {@code false} otherwise
   */
  boolean canSend(SessionKey key);

  /**
   * Returns the earliest time an urgent action is required (ack, finish, retransmit, etc.).
   *
   * @param canSend whether {@link #canSend(SessionKey)} currently permits sending data
   * @param now current time in milliseconds (epoch)
   * @return epoch time in milliseconds, or {@link Long#MAX_VALUE} if nothing is pending
   */
  long timeNextUrgent(boolean canSend, long now);

  /**
   * Returns the scheduled time to send acknowledgments only.
   *
   * <p>Retransmissions and data do not affect this value.
   *
   * @return epoch time in milliseconds for the next ack send, or {@link Long#MAX_VALUE} if none
   */
  long timeSendAcks();

  /**
   * Indicates whether there is enough queued data to justify sending a packet immediately.
   *
   * @param maxPacketSize maximum packet size in bytes, including transport overhead
   * @return {@code true} if at least one near‑full packet can be formed; {@code false} otherwise
   */
  boolean fullPacketQueued(int maxPacketSize);

  /** Scans in‑flight state for losses and schedules any required retransmissions. */
  void checkForLostPackets();

  /**
   * Returns the next time a loss check should run.
   *
   * @return epoch time in milliseconds, or {@link Long#MAX_VALUE} if not needed
   */
  long timeCheckForLostPackets();
}
