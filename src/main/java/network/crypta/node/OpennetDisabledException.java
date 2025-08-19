package network.crypta.node;

import java.io.Serial;

/**
 * Exception thrown when a caller attempts to use opennet functionality, but it is not currently
 * enabled in the node.
 */
public class OpennetDisabledException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  public OpennetDisabledException(Exception e) {
    super(e);
  }

  public OpennetDisabledException(String msg) {
    super(msg);
  }
}
