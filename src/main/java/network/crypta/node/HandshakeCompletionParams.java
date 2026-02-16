package network.crypta.node;

import network.crypta.crypt.BlockCipher;
import network.crypta.io.comm.Peer;

/**
 * Collects handshake completion inputs for a peer connection.
 *
 * <p>This package-private carrier is filled in by the handshake negotiators immediately before the
 * connection state is finalized. The fields are intentionally mutable, so the handshake pipeline
 * can assemble values incrementally without allocating extra objects. Consumers should treat the
 * instance as single-use, populate every required field, and then pass it directly to {@link
 * PeerNodeHandshake#completedHandshake(Object)}. The class performs no validation or defensive
 * copying, so callers remain responsible for nullability, array ownership, and consistency between
 * related fields (for example, ciphers paired with their key material). It is not thread-safe; the
 * typical lifecycle is construction, population on the handshake thread, and immediate handoff for
 * processing.
 *
 * <ul>
 *   <li>Groups noderef payload, negotiated keys, and counters in one object.
 *   <li>Keeps handshake finalization signatures concise without altering behavior.
 *   <li>Relies on the handshake state machine for validation and error handling.
 * </ul>
 */
final class HandshakeCompletionParams {
  /**
   * Creates an empty handshake parameter carrier for the immediate population by the handshake
   * flow.
   *
   * <p>The constructor performs no validation or copying; callers must set all required fields
   * before passing the instance to the completion routine.
   */
  HandshakeCompletionParams() {}

  /** Boot identifier supplied by the peer to detect restarts for this handshake. */
  long thisBootID;

  /** Buffer containing the compressed noderef payload provided by the peer. */
  byte[] data;

  /** Number of valid bytes to read from {@link #data} for noderef parsing. */
  int length;

  /** Cipher initialized for outbound packet encryption with {@link #outgoingKey}. */
  BlockCipher outgoingCipher;

  /** Key material paired with {@link #outgoingCipher}; treated as sensitive and unowned. */
  byte[] outgoingKey;

  /** Cipher initialized for inbound packet decryption with {@link #incommingKey}. */
  BlockCipher incommingCipher;

  /** Key material paired with {@link #incommingCipher}; treated as sensitive and unowned. */
  byte[] incommingKey;

  /** Transport address at which the handshake packet was received. */
  Peer replyTo;

  /** Whether the new tracker should begin in an unverified state. */
  boolean unverified;

  /** Negotiated link setup type identifier for the active handshake. */
  int negType;

  /** Proposed tracker identifier; negative values request allocation of a new ID. */
  long trackerID;

  /** Whether this completion is part of a JFK(4) processing path. */
  boolean isJFK4;

  /** Whether a JFK(4) responder reused the previous tracker identifier. */
  boolean jfk4SameAsOld;

  /** HMAC key used to authenticate session messages after completion. */
  byte[] hmacKey;

  /** Cipher used for IV derivation when establishing the new session. */
  BlockCipher ivCipher;

  /** Nonce material combined with {@link #ivCipher} to derive per-packet IVs. */
  byte[] ivNonce;

  /** Initial outbound packet sequence number for the newly negotiated tracker. */
  int ourInitialSeqNum;

  /** Initial inbound packet sequence number expected for the new tracker. */
  int theirInitialSeqNum;

  /** Initial outbound message identifier for the new session tracker. */
  int ourInitialMsgID;

  /** Initial inbound message identifier expected from the peer for this tracker. */
  int theirInitialMsgID;
}
