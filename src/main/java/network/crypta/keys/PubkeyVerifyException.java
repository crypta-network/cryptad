package network.crypta.keys;

import java.io.Serial;
import network.crypta.crypt.CryptFormatException;

public class PubkeyVerifyException extends KeyVerifyException {

  @Serial private static final long serialVersionUID = 1L;

  public PubkeyVerifyException(CryptFormatException e) {
    super(e);
  }

  public PubkeyVerifyException(String msg) {
    super(msg);
  }
}
