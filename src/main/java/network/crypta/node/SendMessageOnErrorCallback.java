package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** If the send fails, send the given message to the given node. Otherwise do nothing. */
public class SendMessageOnErrorCallback implements AsyncMessageCallback {
  private static final Logger LOG = LoggerFactory.getLogger(SendMessageOnErrorCallback.class);

  static {
  }

  @Override
  public String toString() {
    return super.toString() + ": " + msg + ' ' + dest;
  }

  Message msg;
  PeerNode dest;
  ByteCounter ctr;

  public SendMessageOnErrorCallback(Message message, PeerNode pn, ByteCounter ctr) {
    this.msg = message;
    this.dest = pn;
    this.ctr = ctr;
    if (LOG.isDebugEnabled()) LOG.debug("Created " + this);
  }

  @Override
  public void sent() {
    // Ignore
  }

  @Override
  public void acknowledged() {
    // All done
  }

  @Override
  public void disconnected() {
    if (LOG.isDebugEnabled()) LOG.debug("Disconnect trigger: " + this);
    try {
      dest.sendAsync(msg, null, ctr);
    } catch (NotConnectedException e) {
      if (LOG.isDebugEnabled())
        LOG.debug("Both source and destination disconnected: " + msg + " for " + this);
    }
  }

  @Override
  public void fatalError() {
    disconnected();
  }
}
