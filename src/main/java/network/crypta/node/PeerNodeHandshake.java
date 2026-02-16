package network.crypta.node;

import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.KeyAgreementSchemeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Holds handshake-specific transport and key-agreement context for a {@link PeerNode}.
 *
 * <p>This helper keeps the temporary handshake state separate from the broader peer lifecycle
 * logic. It owns setup ciphers derived from inbound, outbound, and anonymous-initiator setup keys,
 * and it stores the mutable key-agreement context that exists only while a handshake is active.
 *
 * <p>Instances are lightweight and stateful. Cipher references are immutable after construction,
 * while the live key-agreement context is guarded with synchronization to coordinate access across
 * packet-processing and timeout-check paths.
 *
 * <ul>
 *   <li>Exposes setup ciphers required during handshake negotiation.
 *   <li>Tracks the current key-agreement context and supports explicit clearing.
 *   <li>Computes handshake liveness using the shared node handshake timeout policy.
 * </ul>
 */
final class PeerNodeHandshake implements PeerNode.HandshakeState {
  /** Logger for debug-level handshake context transition messages. */
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeHandshake.class);

  /** The owning peer node that receives handshake-completion callbacks. */
  private final PeerNode peerNode;

  /** Setup cipher used for decrypting inbound handshake traffic. */
  private final BlockCipher incomingSetupCipher;

  /** Setup cipher used for encrypting outbound handshake traffic. */
  private final BlockCipher outgoingSetupCipher;

  /** Setup cipher used when the local side initiated an anonymous handshake. */
  private final BlockCipher anonymousInitiatorSetupCipher;

  /** Mutable key-agreement context, or {@code null} when no live handshake is tracked. */
  private KeyAgreementSchemeContext ctx;

  /**
   * Creates a handshake state for a peer and derives setup ciphers from negotiated setup keys.
   *
   * <p>The constructor keeps a reference to the owning peer and uses {@link
   * PeerNodeReferenceSupport} to build ciphers for each handshake direction. The supplied key
   * arrays are interpreted according to the peer reference support cipher contract and are not
   * modified by this class.
   *
   * @param peerNode peer instance that owns this handshake state object.
   * @param incomingSetupKey raw key bytes for inbound setup traffic decryption.
   * @param outgoingSetupKey raw key bytes for outbound setup traffic encryption.
   * @param anonymousInitiatorKey raw key bytes for anonymous initiator setup traffic.
   */
  PeerNodeHandshake(
      PeerNode peerNode,
      byte[] incomingSetupKey,
      byte[] outgoingSetupKey,
      byte[] anonymousInitiatorKey) {
    this.peerNode = peerNode;
    PeerNodeReferenceSupport referenceSupport = new PeerNodeReferenceSupport(peerNode);
    incomingSetupCipher = referenceSupport.buildRijndaelCipher(incomingSetupKey);
    outgoingSetupCipher = referenceSupport.buildRijndaelCipher(outgoingSetupKey);
    anonymousInitiatorSetupCipher = referenceSupport.buildRijndaelCipher(anonymousInitiatorKey);
  }

  /**
   * Returns the setup cipher used for inbound handshake packets.
   *
   * <p>The returned cipher is created during construction and remains stable for the lifetime of
   * this handshake state object.
   *
   * @return cipher configured for decrypting incoming setup traffic.
   */
  @Override
  public BlockCipher incomingSetupCipher() {
    return incomingSetupCipher;
  }

  /**
   * Returns the setup cipher used for outbound handshake packets.
   *
   * <p>The returned cipher is immutable after initialization and is safe to reuse across handshake
   * packet writes for this peer.
   *
   * @return cipher configured for encrypting outgoing setup traffic.
   */
  @Override
  public BlockCipher outgoingSetupCipher() {
    return outgoingSetupCipher;
  }

  /**
   * Returns the setup cipher used during anonymous-initiator handshake traffic.
   *
   * <p>This cipher is prepared once during object creation and reused for the handshake phase.
   *
   * @return cipher configured for anonymous initiator setup packet handling.
   */
  @Override
  public BlockCipher anonymousInitiatorSetupCipher() {
    return anonymousInitiatorSetupCipher;
  }

  /**
   * Returns the current key-agreement context used by the active handshake, if any.
   *
   * <p>Access is synchronized so callers observe a consistent key-agreement context reference when
   * the handshake state is concurrently updated.
   *
   * @return current key-agreement context, or {@code null} when no handshake is active.
   */
  @Override
  public synchronized KeyAgreementSchemeContext getKeyAgreementSchemeContext() {
    return ctx;
  }

  /**
   * Stores the live key-agreement context for the current handshake.
   *
   * <p>The argument is expected to be a {@link KeyAgreementSchemeContext}. The method stores the
   * cast value atomically and emits a debug log entry for handshake diagnostics.
   *
   * @param ctx2 context object that is cast to {@link KeyAgreementSchemeContext} before storage.
   * @throws ClassCastException if {@code ctx2} is not compatible with the expected context type.
   */
  @Override
  public synchronized void setKeyAgreementSchemeContext(Object ctx2) {
    ctx = (KeyAgreementSchemeContext) ctx2;
    if (LOG.isDebugEnabled()) {
      LOG.debug("setKeyAgreementSchemeContext({}) on {}", ctx, peerNode);
    }
  }

  /**
   * Clears the currently tracked key-agreement context.
   *
   * <p>Clearing is synchronized, so later liveness checks and context reads observe the reset state
   * immediately.
   */
  @Override
  public synchronized void clearKeyAgreementSchemeContext() {
    ctx = null;
  }

  /**
   * Determines whether this peer still has a live handshake based on last usage time.
   *
   * <p>The calculation uses the context's last-used timestamp and compares elapsed time against
   * {@link Node#HANDSHAKE_TIMEOUT}. A debug message is emitted when context exists to aid handshake
   * timeout troubleshooting.
   *
   * @param now current wall-clock time in the same time base as {@code lastUsedTime()}.
   * @return {@code true} when a context exists and has not exceeded the handshake timeout window.
   */
  @Override
  public boolean hasLiveHandshake(long now) {
    KeyAgreementSchemeContext localCtx;
    synchronized (this) {
      localCtx = ctx;
    }
    if (localCtx != null && LOG.isDebugEnabled()) {
      LOG.debug("Last used (handshake): {}", now - localCtx.lastUsedTime());
    }
    return localCtx != null && (now - localCtx.lastUsedTime() <= Node.HANDSHAKE_TIMEOUT);
  }

  /**
   * Completes handshake processing by delegating to the owning peer node.
   *
   * <p>This delegates completion handling to the owning {@link PeerNode}, which performs final
   * transition and bookkeeping for the established connection.
   *
   * @param params handshake completion payload expected by {@link
   *     PeerNode#completeHandshake(Object)}.
   * @return completion timestamp or sequence value produced by the owning peer node.
   */
  @Override
  public long completedHandshake(Object params) {
    return peerNode.completeHandshake(params);
  }
}
