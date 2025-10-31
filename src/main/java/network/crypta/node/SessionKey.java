package network.crypta.node;

import network.crypta.crypt.BlockCipher;

/**
 * Holds the cryptographic materials and per-key context for a single peer session.
 *
 * <p>The fields expose the block ciphers and raw key bytes used by the {@link NewPacketFormat}
 * pipeline for encrypting/decrypting packets and computing message authentication. Array fields are
 * stored by reference; they are not defensively copied. Treat all keying material as sensitive and
 * avoid modifying it after construction.
 *
 * <p>Thread safety: instances are immutable with respect to field references. The referenced arrays
 * themselves are mutable. The {@link #packetContext} manages its own synchronization.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class SessionKey {

  /**
   * Owning peer for this session key. May be {@code null} in tests or during construction in
   * transitional states.
   */
  public final PeerNode pn;

  /** Cipher used to encrypt outgoing packets for this session. */
  public final BlockCipher outgoingCipher;

  /**
   * Raw key bytes associated with {@link #outgoingCipher}. Stored by reference; not defensively
   * copied. Handle as secret material.
   */
  public final byte[] outgoingKey;

  /** Cipher used to decrypt incoming packets for this session. */
  public final BlockCipher incommingCipher;

  /**
   * Raw key bytes associated with {@link #incommingCipher}. Stored by reference; not defensively
   * copied. Handle as secret material.
   */
  public final byte[] incommingKey;

  /** Cipher used when deriving or masking per-packet IV material. */
  public final BlockCipher ivCipher;

  /**
   * Base nonce used together with {@link #ivCipher} for IV-related operations. Stored by reference;
   * not defensively copied.
   */
  public final byte[] ivNonce;

  /** Key material used for per-packet authentication (HMAC). Stored by reference. */
  public final byte[] hmacKey;

  /**
   * Opaque tracker identifier for diagnostics. Semantics are defined by the creator; the value is
   * not interpreted by this class.
   */
  final long trackerID;

  /**
   * Per-key packet context that tracks sequence numbers, acknowledgments, and in-flight packets.
   * Must be non-null when {@link #disconnected()} is invoked.
   */
  public final NewPacketFormatKeyContext packetContext;

  /**
   * Creates a new {@code SessionKey} with the provided ciphers, key bytes, and context.
   *
   * <p>All array parameters are stored by reference and are not defensively copied. Callers should
   * avoid modifying them after construction.
   *
   * @param parent owning peer (may be {@code null} in tests).
   * @param outgoingCipher cipher for encrypting outgoing packets.
   * @param outgoingKey raw key bytes for {@code outgoingCipher}; stored by reference.
   * @param incommingCipher cipher for decrypting incoming packets.
   * @param incommingKey raw key bytes for {@code incommingCipher}; stored by reference.
   * @param ivCipher cipher used for IV-related operations.
   * @param ivNonce base nonce used with {@code ivCipher}; stored by reference.
   * @param hmacKey key material used for message authentication; stored by reference.
   * @param context per-key packet context; must be non-null if {@link #disconnected()} will be
   *     called.
   * @param trackerID opaque identifier for diagnostics.
   */
  SessionKey(
      PeerNode parent,
      BlockCipher outgoingCipher,
      byte[] outgoingKey,
      BlockCipher incommingCipher,
      byte[] incommingKey,
      BlockCipher ivCipher,
      byte[] ivNonce,
      byte[] hmacKey,
      NewPacketFormatKeyContext context,
      long trackerID) {
    this.pn = parent;
    this.outgoingCipher = outgoingCipher;
    this.outgoingKey = outgoingKey;
    this.incommingCipher = incommingCipher;
    this.incommingKey = incommingKey;
    this.ivCipher = ivCipher;
    this.ivNonce = ivNonce;
    this.hmacKey = hmacKey;
    this.packetContext = context;
    this.trackerID = trackerID;
  }

  /**
   * Notifies the per-key context that this session key is no longer active.
   *
   * <p>Delegates to {@link NewPacketFormatKeyContext#disconnected()} so that any in-flight packets
   * are marked lost and per-key state is cleared.
   *
   * <p>Precondition: {@link #packetContext} is non-null.
   */
  public void disconnected() {
    packetContext.disconnected();
  }
}
