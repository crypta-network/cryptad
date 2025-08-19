package network.crypta.keys;

import java.io.Serial;

/**
 * @author amphibian
 *     <p>Exception thrown when a CHK encoding fails. Specifically, it is thrown when the data is
 *     too big to encode.
 */
public class CHKEncodeException extends KeyEncodeException {
  @Serial private static final long serialVersionUID = -1;

  public CHKEncodeException() {
    super();
  }

  public CHKEncodeException(String message) {
    super(message);
  }

  public CHKEncodeException(String message, Throwable cause) {
    super(message, cause);
  }

  public CHKEncodeException(Throwable cause) {
    super(cause);
  }
}
