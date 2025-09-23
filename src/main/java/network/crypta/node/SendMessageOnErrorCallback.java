package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;

/** If the send fails, send the given message to the given node. Otherwise do nothing. */
public class SendMessageOnErrorCallback implements AsyncMessageCallback {
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
    return super.toString() + ": " + msg + ' ' + dest;
  }

  Message msg;
  PeerNode dest;
  ByteCounter ctr;

  public SendMessageOnErrorCallback(Message message, PeerNode pn, ByteCounter ctr) {
    this.msg = message;
    this.dest = pn;
    this.ctr = ctr;
    if (logMINOR) Logger.minor(this, "Created " + this);
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
    if (logMINOR) Logger.minor(this, "Disconnect trigger: " + this);
    try {
      dest.sendAsync(msg, null, ctr);
    } catch (NotConnectedException e) {
      if (logMINOR)
        Logger.minor(this, "Both source and destination disconnected: " + msg + " for " + this);
    }
  }

  @Override
  public void fatalError() {
    disconnected();
  }
}
