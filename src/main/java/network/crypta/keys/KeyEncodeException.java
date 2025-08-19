package network.crypta.keys;

import java.io.Serial;

public class KeyEncodeException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  public KeyEncodeException(String string) {
    super(string);
  }

  public KeyEncodeException() {
    super();
  }

  public KeyEncodeException(String message, Throwable cause) {
    super(message, cause);
  }

  public KeyEncodeException(Throwable cause) {
    super(cause);
  }
}
