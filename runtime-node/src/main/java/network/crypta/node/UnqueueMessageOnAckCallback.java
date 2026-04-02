package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Callback that removes a queued node-to-node message once an acknowledgement is received.
 *
 * <p>This is used for N2NM sends that are kept in a resend queue until the remote peer acknowledges
 * receipt. When {@link #acknowledged()} is invoked, it calls {@link
 * DarknetPeerNode#unqueueN2NM(int)} with the provided file number. Other lifecycle methods are
 * no-ops so the message remains queued until an acknowledgement arrives.
 *
 * <p>Logging: construction logs at DEBUG for traceability.
 */
public class UnqueueMessageOnAckCallback implements AsyncMessageCallback {
  private static final Logger LOG = LoggerFactory.getLogger(UnqueueMessageOnAckCallback.class);

  /** Returns a concise representation including the destination and file number. */
  @Override
  public String toString() {
    return super.toString() + ": " + dest + ' ' + extraPeerDataFileNumber;
  }

  // Destination peer associated with the queued message; may be null for tests.
  DarknetPeerNode dest;
  // File number identifying the queued N2NM message in the peer's resend queue.
  int extraPeerDataFileNumber;

  /**
   * Create a callback that unqueues the given file number from the specified peer on
   * acknowledgement.
   *
   * @param pn the destination peer that holds the resend queue; must be non-null when {@link
   *     #acknowledged()} is invoked
   * @param extraPeerDataFileNumber the file number of the queued message to remove on
   *     acknowledgement
   */
  public UnqueueMessageOnAckCallback(DarknetPeerNode pn, int extraPeerDataFileNumber) {
    this.dest = pn;
    this.extraPeerDataFileNumber = extraPeerDataFileNumber;
    if (LOG.isDebugEnabled()) {
      LOG.debug("Create UnqueueMessageOnAckCallback {}", this);
    }
  }

  /** No-op; acknowledgement controls removal from the resend queue. */
  @Override
  public void sent() {
    // No action here; only acknowledged() unqueues.
  }

  /**
   * Unqueues the message after the remote peer acknowledges receipt.
   *
   * @throws NullPointerException if the destination peer is {@code null}
   */
  @Override
  public void acknowledged() {
    // Message is acknowledged; remove it from the resend queue.
    dest.unqueueN2NM(extraPeerDataFileNumber);
  }

  /** No-op; disconnection does not change queue state. */
  @Override
  public void disconnected() {
    // No action; the message remains queued for retry logic elsewhere.
  }

  /** No-op; fatal send errors are handled by higher-level logic. */
  @Override
  public void fatalError() {
    // No action here; this callback only unqueues on acknowledgement.
  }
}
