package network.crypta.node;

import java.io.Serial;

/**
 * Thrown when a peer reference or a "peers" file, once read into a {@link
 * network.crypta.support.SimpleFieldSet SimpleFieldSet}, cannot be interpreted.
 *
 * <p>This checked exception signals a failure while mapping SFS content to the expected domain
 * objects used by the node. The {@linkplain #getMessage() message} and optional {@linkplain
 * #getCause() cause} describe the first encountered problem.
 *
 * <p>Typical reasons include malformed fields, missing required keys, or invalid numeric values.
 * Callers should surface the detail message to users or logs to aid diagnosis.
 */
public class FSParseException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception that wraps an underlying parsing failure.
   *
   * @param e the underlying cause of the parse failure.
   */
  public FSParseException(Exception e) {
    super(e);
  }

  /**
   * Creates an exception with a detail message but no cause.
   *
   * @param msg human-readable description of the parse failure.
   */
  public FSParseException(String msg) {
    super(msg);
  }

  /**
   * Creates an exception with a detail message and a cause.
   *
   * @param msg human-readable description of the parse failure.
   * @param cause the underlying failure; may be {@code null}.
   */
  public FSParseException(String msg, Throwable cause) {
    super(msg, cause);
  }

  /**
   * Creates an exception specialized for numeric parsing errors.
   *
   * <p>The provided message is augmented with the string form of {@code e}, and the cause of this
   * exception is set to {@code e}.
   *
   * @param msg context describing which numeric value failed to parse.
   * @param e the {@link NumberFormatException} encountered during parsing.
   */
  public FSParseException(String msg, NumberFormatException e) {
    super(msg + " : " + e);
    initCause(e);
  }
}
