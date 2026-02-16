package network.crypta.node;

import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.KeyAgreementSchemeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handshake-specific transport and key-agreement context state for a {@link PeerNode}.
 *
 * <p>This helper isolates setup-cipher material and the live key-agreement context so that
 * connection finalization logic in {@link PeerNode} can stay focused on peer state transitions.
 */
final class PeerNodeHandshake implements PeerNode.HandshakeState {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeHandshake.class);

  private final PeerNode peerNode;
  private final BlockCipher incomingSetupCipher;
  private final BlockCipher outgoingSetupCipher;
  private final BlockCipher anonymousInitiatorSetupCipher;

  private KeyAgreementSchemeContext ctx;

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

  @Override
  public BlockCipher incomingSetupCipher() {
    return incomingSetupCipher;
  }

  @Override
  public BlockCipher outgoingSetupCipher() {
    return outgoingSetupCipher;
  }

  @Override
  public BlockCipher anonymousInitiatorSetupCipher() {
    return anonymousInitiatorSetupCipher;
  }

  @Override
  public synchronized KeyAgreementSchemeContext getKeyAgreementSchemeContext() {
    return ctx;
  }

  @Override
  public synchronized void setKeyAgreementSchemeContext(Object ctx2) {
    ctx = (KeyAgreementSchemeContext) ctx2;
    if (LOG.isDebugEnabled()) {
      LOG.debug("setKeyAgreementSchemeContext({}) on {}", ctx, peerNode);
    }
  }

  @Override
  public synchronized void clearKeyAgreementSchemeContext() {
    ctx = null;
  }

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

  @Override
  public long completedHandshake(Object params) {
    return peerNode.completeHandshake(params);
  }
}
