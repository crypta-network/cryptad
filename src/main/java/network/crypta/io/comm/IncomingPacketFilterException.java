package network.crypta.io.comm;

import java.io.Serial;
import network.crypta.support.LightweightException;

public class IncomingPacketFilterException extends LightweightException {
  @Serial private static final long serialVersionUID = -1;

  public IncomingPacketFilterException(String string) {
    super(string);
  }

  public IncomingPacketFilterException() {
    super();
  }
}
