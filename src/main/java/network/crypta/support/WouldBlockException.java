package network.crypta.support;

import java.io.Serial;
import network.crypta.io.comm.IncomingPacketFilterException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Thrown when we would have to block but have been told not to. */
public class WouldBlockException extends IncomingPacketFilterException {
  private static final Logger LOG = LoggerFactory.getLogger(WouldBlockException.class);

  @Serial private static final long serialVersionUID = -1;

  static {
  }

  public WouldBlockException(String string) {
    super(string);
  }

  public WouldBlockException() {
    super();
  }

  @Override
  protected boolean shouldFillInStackTrace() {
    return LOG.isDebugEnabled();
  }
}
