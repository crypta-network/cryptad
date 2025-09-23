package network.crypta.crypt;

import java.io.Serial;

public class UnsupportedCipherException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  public UnsupportedCipherException() {}

  public UnsupportedCipherException(String s) {
    super(s);
  }
}
