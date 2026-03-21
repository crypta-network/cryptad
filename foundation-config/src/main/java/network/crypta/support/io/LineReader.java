package network.crypta.support.io;

import java.io.IOException;

/**
 * Minimal abstraction for reading a single text line from a byte-oriented source.
 *
 * <p>Implementations read a line terminated by LF ({@code '\n'}) or CRLF ({@code "\r\n"}), decode
 * it using either UTF-8 or ISO-8859-1 as directed, and return the line content without the
 * line-termination characters. At end of stream, if no bytes were read for the next line, {@code
 * null} is returned; otherwise the remaining bytes are decoded and returned as the final line.
 *
 * <p>The primary purpose of this interface is to allow components to consume lines from different
 * sources consistently (e.g., {@link java.io.BufferedReader} via an adapter, or {@link
 * LineReadingInputStream}). Implementations may enforce a maximum line length to bound memory
 * usage.
 *
 * <p>Thread-safety: Implementations are not required to be thread-safe unless stated otherwise by
 * the concrete type.
 */
public interface LineReader {

  /**
   * Reads one LF or CRLF-terminated line and decodes it as UTF-8 or ISO-8859-1.
   *
   * <p>The returned string never includes the line-termination characters. If end-of-stream is
   * reached before any byte is read for the next line, this method returns {@code null}; if some
   * bytes were read but no terminator was found before EOF, the decoded bytes are returned as the
   * final line.
   *
   * @param maxLength Upper bound on the number of bytes to consume before the terminator (not
   *     including the terminator). Implementations should throw {@link TooLongException} when this
   *     limit is exceeded to prevent unbounded buffering; adapters may ignore the limit.
   * @param bufferSize Hint for the initial internal buffer capacity; implementations may clamp or
   *     ignore this value.
   * @param utf When {@code true}, decode as UTF-8; when {@code false}, decode as ISO-8859-1. No
   *     other encodings are supported.
   * @return The decoded line text without the line-termination characters, or {@code null} at
   *     end-of-stream when no byte was read for the next line.
   * @throws TooLongException if the line exceeds {@code maxLength} (subclass of {@link
   *     IOException}).
   * @throws IOException on I/O errors or if the underlying stream violates its contract (e.g.,
   *     returning zero from a blocking read).
   */
  String readLine(int maxLength, int bufferSize, boolean utf) throws IOException;
}
