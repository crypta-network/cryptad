package network.crypta.crypt;

import java.io.IOException;
import java.io.Serial;

public class CryptFormatException extends Exception {

  @Serial private static final long serialVersionUID = -796276279268900609L;

  public CryptFormatException(String message) {
    super(message);
  }

  public CryptFormatException(IOException e) {
    super(e.getMessage());
    initCause(e);
  }
}
