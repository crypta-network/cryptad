package network.crypta.keys;

import java.io.Serial;

/**
 * @author amphibian
 *     <p>Exception thrown when a CHK doesn't verify.
 */
public class CHKVerifyException extends KeyVerifyException {
  @Serial private static final long serialVersionUID = -1;

  public CHKVerifyException() {
    super();
  }

  public CHKVerifyException(String message) {
    super(message);
  }

  public CHKVerifyException(String message, Throwable cause) {
    super(message, cause);
  }

  public CHKVerifyException(Throwable cause) {
    super(cause);
  }
}
