package network.crypta.clients.http;

import java.io.Serial;
import network.crypta.support.LightweightException;

/**
 * Signals invalid or unsupported HTTP Range headers encountered while parsing client requests.
 *
 * <p>The exception is raised when range syntax is malformed (missing bounds, wrong units, negative
 * offsets) or when offsets conflict with expected ordering. Callers typically surface this as a 416
 * response or fall back to sending the entire resource. The class is lightweight and intended for
 * control flow rather than detailed error reporting; it carries only a message or root cause.
 *
 * <p>Typical usage wraps the parsing routine: if {@link HTTPRangeException} is thrown, respond with
 * an error status instead of attempting partial I/O. Instances are immutable and thread-safe.
 */
public class HTTPRangeException extends LightweightException {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates a new range exception with the supplied root cause.
   *
   * @param cause underlying parsing or numeric error that triggered the range failure; must be
   *     non-null for diagnostic clarity.
   */
  public HTTPRangeException(Throwable cause) {
    super(cause);
  }

  /**
   * Creates a new range exception with a descriptive message.
   *
   * @param msg human-readable description of the invalid range condition; empty messages are
   *     accepted but discouraged for troubleshooting.
   */
  public HTTPRangeException(String msg) {
    super(msg);
  }
}
