package network.crypta.support;

import java.io.Serial;
import network.crypta.io.comm.IncomingPacketFilterException;
import network.crypta.support.Logger.LogLevel;

/** Thrown when we would have to block but have been told not to. */
public class WouldBlockException extends IncomingPacketFilterException {

  @Serial private static final long serialVersionUID = -1;
  private static volatile boolean logDEBUG;

  static {
    Logger.registerLogThresholdCallback(
        new LogThresholdCallback() {

          @Override
          public void shouldUpdate() {
            logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
          }
        });
  }

  public WouldBlockException(String string) {
    super(string);
  }

  public WouldBlockException() {
    super();
  }

  @Override
  protected boolean shouldFillInStackTrace() {
    return logDEBUG;
  }
}
