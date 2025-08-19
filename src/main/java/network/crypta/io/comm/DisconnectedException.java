package network.crypta.io.comm;

import java.io.Serial;
import network.crypta.support.LightweightException;

/**
 * Thrown when the node is disconnected in the middle of (or at the beginning of) a waitFor(). Not
 * the same as NotConnectedException.
 */
public class DisconnectedException extends LightweightException {
  @Serial private static final long serialVersionUID = -1;
}
