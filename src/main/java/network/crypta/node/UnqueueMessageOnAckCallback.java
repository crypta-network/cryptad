package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** If the send fails, queue the given message for the given node. Otherwise do nothing. */
public class UnqueueMessageOnAckCallback implements AsyncMessageCallback {
    private static final Logger LOG = LoggerFactory.getLogger(UnqueueMessageOnAckCallback.class);

  static {
    
  }

  @Override
  public String toString() {
    return super.toString() + ": " + dest + ' ' + extraPeerDataFileNumber;
  }

  DarknetPeerNode dest;
  int extraPeerDataFileNumber;

  public UnqueueMessageOnAckCallback(DarknetPeerNode pn, int extraPeerDataFileNumber) {
    this.dest = pn;
    this.extraPeerDataFileNumber = extraPeerDataFileNumber;
    if (LOG.isDebugEnabled()) {
      LOG.debug("Created " + this);
    }
  }

  @Override
  public void sent() {
    // Ignore
  }

  @Override
  public void acknowledged() {
    // the message was received, no need to try again.
    dest.unqueueN2NM(extraPeerDataFileNumber);
  }

  @Override
  public void disconnected() {
    // ignore
  }

  @Override
  public void fatalError() {
    // ignore
  }
}
