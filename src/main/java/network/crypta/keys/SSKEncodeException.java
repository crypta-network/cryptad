package network.crypta.keys;

import java.io.Serial;

public class SSKEncodeException extends KeyEncodeException {
  @Serial private static final long serialVersionUID = -1;

  public SSKEncodeException(String message, KeyEncodeException e) {
    super(message, e);
  }
}
