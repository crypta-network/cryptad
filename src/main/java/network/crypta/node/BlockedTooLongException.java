package network.crypta.node;

import java.io.Serial;

public class BlockedTooLongException extends Exception {
  @Serial private static final long serialVersionUID = 1L;

  public final long delta;

  public BlockedTooLongException(long delta) {
    this.delta = delta;
  }
}
