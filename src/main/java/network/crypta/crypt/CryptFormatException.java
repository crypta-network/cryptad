package network.crypta.crypt;

import java.io.IOException;
import java.io.Serial;

/**
 * Signals that cryptographic input does not conform to the expected Crypta serialization or wire
 * format.
 *
 * <p>Typical causes include truncated data, invalid headers, unsupported versions, or other
 * inconsistencies detected while parsing or verifying cryptographic material. This is a checked
 * exception so callers handle format errors explicitly. When constructed from an {@link
 * IOException}, the original exception becomes the cause.
 *
 * @see IOException
 */
public class CryptFormatException extends Exception {

  @Serial private static final long serialVersionUID = -796276279268900609L;

  /**
   * Creates an exception with a descriptive message about the detected format problem.
   *
   * @param message detail message describing the format error.
   */
  public CryptFormatException(String message) {
    super(message);
  }

  /**
   * Creates an exception that wraps an {@link IOException} encountered while reading or parsing
   * cryptographic data.
   *
   * <p>The message from the provided exception is used as this exception's detail message, and the
   * cause is initialized to the provided exception to preserve its stack trace.
   *
   * @param e the underlying I/O error that led to detecting the format problem.
   */
  public CryptFormatException(IOException e) {
    super(e.getMessage());
    // Preserve the original IOException as the cause to retain its stack trace.
    initCause(e);
  }
}
