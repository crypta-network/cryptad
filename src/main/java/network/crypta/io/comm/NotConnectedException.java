package network.crypta.io.comm;

import java.io.Serial;
import network.crypta.support.LightweightException;

/**
 * @author amphibian
 *     <p>Exception thrown when we try to send a message to a node that is not currently connected.
 */
public class NotConnectedException extends LightweightException {
  @Serial private static final long serialVersionUID = -1;

  public NotConnectedException(String string) {
    super(string);
  }

  public NotConnectedException() {
    super();
  }

  public NotConnectedException(DisconnectedException e) {
    super(e.toString());
    initCause(e);
  }
}
