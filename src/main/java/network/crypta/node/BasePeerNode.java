package network.crypta.node;

import java.util.Random;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.Peer.LocalAddressException;
import network.crypta.io.comm.PeerContext;

/**
 * Transport-facing view of a peer connection.
 *
 * <p>This interface is implemented by {@link PeerNode} and consumed by the packet-format and socket
 * code paths. It exposes just enough state and callbacks for encrypting/decrypting, accounting,
 * throttling, and key rollover without coupling those components to the full {@code PeerNode}.
 * Implementations are expected to be thread-safe where noted (e.g., byte counters and timing data
 * are updated from I/O threads).
 *
 * <p>Unit tests may provide minimal implementations (e.g., {@code NullBasePeerNode}) to exercise
 * transport logic in isolation.
 *
 * @author toad
 */
public interface BasePeerNode extends PeerContext {

  /**
   * Returns the currently preferred session for sending and receiving data packets.
   *
   * <p>The returned tracker may be {@code null} if the peer is disconnected or a handshake has not
   * completed.
   *
   * @return the active {@link SessionKey}, or {@code null} when none is available
   */
  SessionKey getCurrentKeyTracker();

  /**
   * Returns the session key used immediately prior to the current one.
   *
   * <p>This tracker is kept for a short period during rekeying to allow late acks and ack-only
   * packets to be processed. It may be {@code null}.
   *
   * @return the previous {@link SessionKey}, or {@code null}
   */
  SessionKey getPreviousKeyTracker();

  /**
   * Returns the not-yet-verified session created during rekeying.
   *
   * <p>This tracker is promoted to the current tracker after a packet decrypts successfully on it
   * (see {@link #verified(SessionKey)}). It may be {@code null}.
   *
   * @return the unverified {@link SessionKey}, or {@code null}
   */
  SessionKey getUnverifiedKeyTracker();

  /**
   * Records that a packet was received and updates timing state.
   *
   * @param dontLog when {@code true}, suppresses disconnected warnings during early handshake or
   *     teardown paths
   * @param dataPacket {@code true} if this was a data packet (not only handshake/auth)
   */
  void receivedPacket(boolean dontLog, boolean dataPacket);

  /**
   * Notifies that a packet decrypted successfully on the given session key.
   *
   * <p>Typical implementations promote the unverified tracker to current and demote the old current
   * tracker when {@code s} equals the unverified tracker.
   *
   * @param s the {@link SessionKey} that successfully verified/decrypted a packet
   */
  void verified(SessionKey s);

  /**
   * Initiates a rekey handshake.
   *
   * <p>Non-blocking: schedules any required work to refresh the session keys.
   */
  void startRekeying();

  /**
   * Re-evaluates whether rekeying is required and triggers it if conditions are met.
   *
   * <p>Conditions typically include elapsed time since the last key change or bytes sent on the
   * current session.
   */
  void maybeRekey();

  /**
   * Reports that {@code length} bytes were received from the peer.
   *
   * @param length number of bytes; non-negative
   */
  void reportIncomingBytes(int length);

  /**
   * Reports that {@code length} bytes were sent to the peer.
   *
   * @param length number of bytes; non-negative
   */
  void reportOutgoingBytes(int length);

  /**
   * Starts a batch for decoding and dispatching decrypted messages.
   *
   * <p>The returned {@link DecodingMessageGroup} should be used to process up to {@code count}
   * messages and then {@code complete()} must be called to finish dispatching.
   *
   * @param count expected number of messages in this batch (advisory hint)
   * @return a group used to decode and deliver messages from the current packet
   */
  default DecodingMessageGroup startProcessingDecryptedMessages(int count) {
    return transport().startProcessingDecryptedMessages(count);
  }

  /**
   * Reports a measured round-trip time sample for this peer.
   *
   * <p>Implementations use this to update SRTT/RTTVAR and recompute the retransmission timeout
   * (RTO) as per RFC 2988.
   *
   * @param rt round-trip time in milliseconds
   */
  void reportPing(long rt);

  /**
   * Returns the exponentially-weighted moving average of recent ping samples.
   *
   * @return average round-trip time in milliseconds
   */
  double averagePingTime();

  /** Wakes the sender so it can schedule outbound packets promptly. */
  void wakeUpSender();

  /**
   * Returns the maximum serialized size of a single encrypted packet that can be sent to this peer.
   *
   * @return maximum packet size in bytes
   */
  int getMaxPacketSize();

  /**
   * Returns the message queue backing this connection.
   *
   * @return the {@link PeerMessageQueue} used by the transport
   */
  PeerMessageQueue getMessageQueue();

  /**
   * Indicates whether data packets should be padded to obscure their true size.
   *
   * @return {@code true} when padding is enabled
   */
  boolean shouldPadDataPackets();

  /**
   * Sends a fully formed encrypted packet to the peer.
   *
   * <p>The buffer contains the complete on-the-wire representation (HMAC, headers, ciphertext,
   * padding). The implementation forwards it to the configured socket/transport.
   *
   * @param data packet bytes to transmit; the caller may re-use the array after the method returns
   * @throws LocalAddressException if the destination resolves to a local address and local sends
   *     are disallowed by configuration
   */
  void sendEncryptedPacket(byte[] data) throws LocalAddressException;

  /** Records that a packet was sent (used for keepalive and timeout computations). */
  void sentPacket();

  /**
   * Returns whether outbound traffic should be accounted against the node's throttle for this
   * destination.
   *
   * @return {@code true} if the send should be throttled
   */
  boolean shouldThrottle();

  /**
   * Accounts throttled bytes against the appropriate output throttle.
   *
   * @param length number of bytes that were throttled
   */
  void sentThrottledBytes(int length);

  /**
   * Reports that a packet carried only notifications/acks and no payload.
   *
   * @param length total packet length in bytes
   */
  void onNotificationOnlyPacketSent(int length);

  /**
   * Reports that previously sent data had to be retransmitted.
   *
   * @param bytesToResend number of bytes resent
   */
  void resentBytes(int bytesToResend);

  /**
   * Returns a non-cryptographic PRNG used for packet padding and other transport-local randomness.
   *
   * @return a {@link Random} instance safe for concurrent use by the transport
   */
  Random paddingGen();

  /**
   * Handles a decoded message destined for higher layers.
   *
   * <p>Implementations typically validate filters and hand the message to the node's message
   * switch/multiplexer.
   *
   * @param msg the decoded {@link Message}
   */
  default void handleMessage(Message msg) {
    transport().handleMessage(msg);
  }

  /**
   * Returns the current retransmission timeout (RTO) derived from SRTT/RTTVAR.
   *
   * <p>The value follows TCP's RFC 2988 computation and incorporates variance, providing a
   * conservative estimate for scheduling retransmissions.
   *
   * @return RTO in milliseconds
   */
  double averagePingTimeCorrected();

  /**
   * Backs off the retransmission timers after a resend.
   *
   * <p>Typically doubles the current RTO with an upper bound, consistent with RFC 2988 guidance.
   */
  void backoffOnResend();

  /**
   * Records the time at which an outgoing packet was acknowledged.
   *
   * @param currentTimeMillis wall-clock time in milliseconds since the epoch
   */
  void receivedAck(long currentTimeMillis);
}
