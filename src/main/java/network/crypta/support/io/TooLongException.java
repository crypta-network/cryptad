package network.crypta.support.io;

import java.io.IOException;
import java.io.Serial;

/**
 * Signals that a line read from a stream exceeds the configured maximum length.
 *
 * <p>This checked {@link IOException} is thrown by {@link LineReadingInputStream} when the number
 * of bytes accumulated for a single logical line (excluding the line terminator) grows beyond the
 * caller-specified bound. The limit applies to raw bytes, not Unicode code points, so multibyte
 * characters in UTF-8 count toward the limit by their encoded length.
 *
 * <p>Callers can catch this exception to abort parsing of the current artifact while keeping the
 * underlying stream in a well-defined position. See {@link LineReadingInputStream#readLine(int,
 * int, boolean)} for details on how the stream is advanced on success and on failure.
 */
public class TooLongException extends IOException {
  /** Serialization version for compatibility across releases. */
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates the exception with a detail message describing the length violation.
   *
   * @param s human-readable description of the error; may be {@code null}.
   */
  TooLongException(String s) {
    super(s);
  }
}
