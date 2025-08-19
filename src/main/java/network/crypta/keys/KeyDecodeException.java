package network.crypta.keys;

import java.io.Serial;

/** Base class for decode exceptions. */
public class KeyDecodeException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  public KeyDecodeException(String message) {
    super(message);
  }

  public KeyDecodeException() {
    super();
  }

  public KeyDecodeException(String message, Throwable cause) {
    super(message, cause);
  }

  public KeyDecodeException(Throwable cause) {
    super(cause);
  }
}
