package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Callback that forwards a prepared message on send failure.
 *
 * <p>This implementation does nothing for successful sends and acknowledgements. If the original
 * connection is closed or a fatal error is reported, it attempts to asynchronously send the
 * provided {@link Message} to the specified {@link PeerNode} using the supplied {@link
 * ByteCounter}.
 *
 * <p>Thread-safety: instances are typically used by transport code and may be invoked on I/O
 * threads. The forwarding call uses {@code PeerNode.transport().sendAsync(...)} and returns
 * immediately.
 *
 * <p>Failure handling: if the destination is not connected, the attempt is ignored and a debug log
 * entry is written.
 */
public class SendMessageOnErrorCallback implements AsyncMessageCallback {
  private static final Logger LOG = LoggerFactory.getLogger(SendMessageOnErrorCallback.class);

  /**
   * Returns a concise diagnostic string with the message and destination.
   *
   * @return a string useful for logs and debugging
   */
  @Override
  public String toString() {
    return super.toString() + ": " + msg + ' ' + dest;
  }

  Message msg;
  PeerNode dest;
  ByteCounter ctr;

  /**
   * Creates a callback that forwards {@code message} to {@code pn} on disconnect or fatal error.
   *
   * @param message the message to re-send if an error occurs
   * @param pn the destination peer that should receive the message on error
   * @param ctr the byte counter to account for outbound bytes when forwarding
   */
  public SendMessageOnErrorCallback(Message message, PeerNode pn, ByteCounter ctr) {
    this.msg = message;
    this.dest = pn;
    this.ctr = ctr;
    if (LOG.isDebugEnabled()) LOG.debug("Initialize callback {}", this);
  }

  /** Called when the message is sent. No follow-up action is required. */
  @Override
  public void sent() {
    // No action required after successful send.
  }

  /** Called when the peer acknowledges the message. No further work is needed. */
  @Override
  public void acknowledged() {
    // No action required after acknowledgment.
  }

  /**
   * Called when the connection disconnects. Attempts to forward the message to the destination peer
   * asynchronously. If the destination is not connected, the attempt is ignored.
   */
  @Override
  public void disconnected() {
    if (LOG.isDebugEnabled()) LOG.debug("Disconnect event for {}", this);
    try {
      dest.transport().sendAsync(msg, null, ctr);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Source and destination disconnected: {} for {}", msg, this);
    }
  }

  /**
   * Called when a fatal error occurs. Delegates to {@link #disconnected()} to attempt forwarding.
   */
  @Override
  public void fatalError() {
    disconnected();
  }
}
