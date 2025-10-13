package network.crypta.support.io;

import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import network.crypta.support.HexUtil;
import org.jetbrains.annotations.NotNull;

/**
 * InputStream wrapper that reads a single LF or CRLF-terminated line.
 *
 * <p>This class implements {@link LineReader} on top of a byte-oriented {@link InputStream} and
 * returns decoded text lines without the line-termination characters. It supports two encodings:
 * UTF-8 and ISO-8859-1. A line terminates on LF ({@code '\n'}). If the byte immediately preceding
 * the LF is CR ({@code '\r'}), that CR is stripped, thus supporting ordinary CRLF sequences.
 *
 * <p>When the underlying stream supports marking (see {@link InputStream#markSupported()}), the
 * implementation uses {@link #mark(int)} and {@link #reset()} to probe for a terminator and then
 * repositions the stream so that, on return, the next byte to read is the one immediately after the
 * line terminator. When marking is not supported, it falls back to reading one byte at a time and
 * stops once a terminator is encountered or the stream ends. In both cases, the underlying stream
 * is advanced to just after the terminator (or to end-of-stream if no terminator is found).
 *
 * <p>Limits and safety: callers provide an upper bound for the number of bytes that may be consumed
 * for a single line (exclusive of the terminator). If the bound is exceeded, a {@link
 * TooLongException} is thrown to avoid unbounded buffering. The method returns {@code null} at
 * end-of-stream when zero bytes are available for the next line; otherwise any remaining bytes are
 * decoded and returned as the final line, even if they are not terminated.
 *
 * <p>Thread-safety: instances are not thread-safe. Synchronize externally if multiple threads may
 * read concurrently.
 */
public class LineReadingInputStream extends FilterInputStream implements LineReader {

  /**
   * Creates a new line-reading wrapper over the given stream.
   *
   * <p>The provided stream may or may not support marking. If it does, this class uses mark/reset
   * to detect the line terminator efficiently while leaving the stream positioned just after the
   * line. Otherwise, the implementation reads byte-by-byte until a terminator is found or the end
   * of the stream is reached.
   *
   * @param in the underlying input stream. The constructor does not buffer or change the stream's
   *     configuration.
   */
  public LineReadingInputStream(InputStream in) {
    super(in);
  }

  /**
   * Reads one LF or CRLF-terminated line and decodes it as UTF-8 or ISO-8859-1.
   *
   * <p>The returned string never includes the line-termination characters. If end-of-stream is
   * reached before any byte is available for the next line, this method returns {@code null}; if
   * some bytes were read but no terminator was found before EOF, the decoded bytes are returned as
   * the final line.
   *
   * <p>Special case: when {@code maxLength < 1}, this method returns {@code null} without reading
   * from the stream.
   *
   * @param maxLength maximum number of bytes to buffer for the line content (excludes the
   *     terminator). Exceeding this limit causes a {@link TooLongException}.
   * @param bufferSize hint for the initial internal buffer capacity. The implementation clamps the
   *     actual initial capacity between {@code min(128, maxLength)} and {@code 1024} bytes and, if
   *     {@code bufferSize >= maxLength}, sets it to {@code maxLength + 1} to account for an
   *     optional trailing CR.
   * @param utf when {@code true}, decode as UTF-8; when {@code false}, decode as ISO-8859-1.
   * @return decoded line text without the terminator, or {@code null} at end-of-stream when no
   *     bytes were available for a new line.
   * @throws TooLongException if the line exceeds {@code maxLength}.
   * @throws EOFException if a blocking read unexpectedly returns zero bytes (prevents busy loops).
   * @throws IOException on I/O errors.
   */
  @Override
  public String readLine(int maxLength, int bufferSize, boolean utf) throws IOException {
    if (maxLength < 1) return null;
    if (maxLength <= bufferSize)
      bufferSize =
          maxLength + 1; // If requested buffer covers or exceeds maxLength, cap to maxLength+1
    // (extra 1 accounts for a possible preceding CR before LF).

    if (!markSupported()) return readLineWithoutMarking(maxLength, bufferSize, utf);

    byte[] buf = new byte[initialBufferSize(maxLength, bufferSize)];
    int ctr = 0;
    final Charset cs = utf ? StandardCharsets.UTF_8 : StandardCharsets.ISO_8859_1;
    mark(maxLength + 2); // Allow room for both CR and LF following up to maxLength content.
    return readMarkedLoop(buf, ctr, maxLength, bufferSize, cs);
  }

  /**
   * Non-marking variant used when {@link #markSupported()} is {@code false}.
   *
   * <p>Behavior matches {@link #readLine(int, int, boolean)} with the difference that the
   * implementation does not rely on {@code mark}/{@code reset}. Exposed as {@code protected} to
   * facilitate testing and reuse in subclasses.
   *
   * @param maxLength maximum number of bytes to buffer (excludes the terminator)
   * @param bufferSize initial buffer size hint (subject to clamping)
   * @param utf when {@code true}, decode as UTF-8; when {@code false}, decode as ISO-8859-1
   * @return decoded line without the terminator, or {@code null} at end-of-stream when no byte was
   *     available for a new line
   * @throws TooLongException if the line exceeds {@code maxLength}
   * @throws IOException on I/O errors
   */
  protected String readLineWithoutMarking(int maxLength, int bufferSize, boolean utf)
      throws IOException {
    if (maxLength < bufferSize)
      bufferSize =
          maxLength + 1; // If buffer exceeds maxLength, cap to maxLength+1 (allow for optional CR).
    byte[] buf = new byte[initialBufferSize(maxLength, bufferSize)];
    int ctr = 0;
    final Charset cs = utf ? StandardCharsets.UTF_8 : StandardCharsets.ISO_8859_1;
    NonMarkedState s = new NonMarkedState(buf, ctr);
    while (true) {
      processChunkNonMarked(s, maxLength, cs);
      if (s.done) return s.line;
      // Grow after append: processChunkNonMarked writes one byte at index s.ctr.
      // If that write filled the buffer (s.ctr == length), we expand here before next append.
      if (s.ctr >= s.buf.length) {
        s.buf = Arrays.copyOf(s.buf, Math.min(s.buf.length * 2, maxLength));
      }
    }
  }

  /**
   * Delegates bulk reads to the underlying stream.
   *
   * <p>Returns {@code 0} immediately when {@code len == 0}; otherwise forwards to {@link
   * InputStream#read(byte[], int, int)} on the wrapped stream.
   *
   * @param b destination buffer
   * @param off offset within {@code b}
   * @param len maximum number of bytes to read
   * @return number of bytes read, or {@code -1} on end-of-stream
   * @throws IOException on I/O errors
   */
  @Override
  public int read(byte @NotNull [] b, int off, int len) throws IOException {
    if (len == 0) return 0;
    return in.read(b, off, len);
  }

  private String readMarkedLoop(byte[] buf, int ctr, int maxLength, int bufferSize, Charset cs)
      throws IOException {
    MarkedState s = new MarkedState(buf, ctr);
    while (true) {
      processChunkMarked(s, maxLength, bufferSize, cs);
      if (s.done) return s.line;
    }
  }

  private void processChunkMarked(MarkedState s, int maxLength, int bufferSize, Charset cs)
      throws IOException {
    assert (s.buf.length - s.ctr > 0);
    int x = read(s.buf, s.ctr, s.buf.length - s.ctr);
    if (x < 0) {
      s.done = true;
      s.line = (s.ctr == 0) ? null : decode(s.buf, s.ctr, cs);
      return;
    }
    if (x == 0) {
      // Prevent busy-looping when a blocking read yields 0 bytes; treat as terminal.
      throw new EOFException();
    }
    int end = s.ctr + x;

    int lf = indexOfLF(s.buf, s.ctr, end);
    if (lf >= 0) {
      s.done = true;
      s.line = buildLineToReturn(s.buf, lf, cs);
      // Rewind to the last mark and advance past the terminator so the caller observes
      // the stream positioned immediately after the line just returned.
      reset();
      skipNBytes(lf + 1L);
      return;
    }

    // No LF found in the bytes just read; update counter and enforce maxLength.
    s.ctr = end;
    if (s.ctr > maxLength) {
      // Include up to maxLength bytes in the message to aid diagnostics.
      throw new TooLongException(
          "We reached maxLength="
              + maxLength
              + " parsing\n "
              + HexUtil.bytesToHex(s.buf, 0, maxLength)
              + "\n"
              + decode(s.buf, maxLength, cs));
    }

    if (shouldGrow(s.buf.length, s.ctr, bufferSize, maxLength)) {
      s.buf = grow(s.buf, s.ctr, maxLength);
    }
  }

  private static final class MarkedState {
    byte[] buf;
    int ctr;
    boolean done;
    String line;

    MarkedState(byte[] buf, int ctr) {
      this.buf = buf;
      this.ctr = ctr;
    }
  }

  private static int indexOfLF(byte[] buf, int start, int end) {
    for (int i = start; i < end; i++) {
      if (buf[i] == '\n') return i;
    }
    return -1;
  }

  private static String decode(byte[] buf, int len, Charset cs) {
    return new String(buf, 0, len, cs);
  }

  private static int initialBufferSize(int maxLength, int bufferSize) {
    int low = Math.min(128, maxLength);
    return Math.clamp(bufferSize, low, 1024);
  }

  private static boolean shouldGrow(int currentLength, int used, int bufferSize, int maxLength) {
    return (currentLength < maxLength) && (currentLength - used < bufferSize);
  }

  private static byte[] grow(byte[] buf, int used, int maxLength) {
    byte[] newBuf = new byte[Math.min(buf.length * 2, maxLength)];
    System.arraycopy(buf, 0, newBuf, 0, used);
    return newBuf;
  }

  private static String buildLineToReturn(byte[] buf, int lfIndex, Charset cs) {
    if (lfIndex == 0) return "";
    boolean removeCR = (buf[lfIndex - 1] == '\r');
    int end = removeCR ? lfIndex - 1 : lfIndex;
    return decode(buf, end, cs);
  }

  private void processChunkNonMarked(NonMarkedState s, int maxLength, Charset cs)
      throws IOException {
    int x = read();
    if (x == -1) {
      s.done = true;
      s.line = (s.ctr == 0) ? null : decode(s.buf, s.ctr, cs);
      return;
    }
    // Checking for LF by byte value is safe for UTF-8 and ISO-8859-1 (LF is ASCII in both).
    if (x == '\n') {
      s.done = true;
      int len = (s.ctr > 0 && s.buf[s.ctr - 1] == '\r') ? s.ctr - 1 : s.ctr;
      s.line = decode(s.buf, len, cs);
      return;
    }
    if (s.ctr >= maxLength)
      // Enforce maximum length before appending the next byte.
      throw new TooLongException(
          "We reached maxLength="
              + maxLength
              + " parsing\n "
              + HexUtil.bytesToHex(s.buf, 0, s.ctr)
              + "\n"
              + decode(s.buf, s.ctr, cs));
    // Safe to append: on entry we have s.ctr < s.buf.length. If this writing fills the buffer,
    // the caller grows capacity before the next iteration (see growth check in the loop above).
    s.buf[s.ctr++] = (byte) x;
  }

  private static final class NonMarkedState {
    byte[] buf;
    int ctr;
    boolean done;
    String line;

    NonMarkedState(byte[] buf, int ctr) {
      this.buf = buf;
      this.ctr = ctr;
    }
  }
}
