package network.crypta.keys;

import java.io.Serial;

/** Thrown when an SSK fails to verify at the node level. */
public class SSKVerifyException extends KeyVerifyException {
  @Serial private static final long serialVersionUID = -1;

  public SSKVerifyException(String string) {
    super(string);
  }
}
