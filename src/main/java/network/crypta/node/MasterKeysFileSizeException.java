package network.crypta.node;

import java.io.Serial;

public class MasterKeysFileSizeException extends Exception {

  @Serial private static final long serialVersionUID = -2753942792186990130L;

  public final boolean tooBig;

  public MasterKeysFileSizeException(boolean tooBig) {
    this.tooBig = tooBig;
  }

  public boolean isTooBig() {
    return tooBig;
  }

  public String sizeToString() {
    return tooBig ? "big" : "small";
  }
}
