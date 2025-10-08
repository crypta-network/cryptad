package network.crypta.store;

import java.io.Serial;
import network.crypta.support.LightweightException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyCollisionException extends LightweightException {
  private static final Logger LOG = LoggerFactory.getLogger(KeyCollisionException.class);

  @Serial private static final long serialVersionUID = -1;

  static {
  }

  @Override
  protected boolean shouldFillInStackTrace() {
    return LOG.isDebugEnabled();
  }
}
