package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;

/** If the send fails, queue the given message for the given node. Otherwise do nothing. */
public class UnqueueMessageOnAckCallback implements AsyncMessageCallback {
  private static volatile boolean logMINOR;

  static {
    Logger.registerLogThresholdCallback(
        new LogThresholdCallback() {
          @Override
          public void shouldUpdate() {
            logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
          }
        });
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
    if (logMINOR) {
      Logger.minor(this, "Created " + this);
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
