package network.crypta.support.io;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.jetbrains.annotations.NotNull;

/**
 * Utilities for composing streams with fixed headers.
 *
 * <p>This helper provides wrappers that either virtually prepend a header to an {@link InputStream}
 * or enforce and swallow a required header on an {@link OutputStream}. These are useful when a
 * protocol requires a deterministic prefix, but you do not want to materialize a new byte array or
 * touch the underlying stream sources/sinks.
 *
 * <p>Thread-safety: the returned wrappers are not thread-safe and follow the usual {@code
 * InputStream}/{@code OutputStream} concurrency expectations.
 *
 * @author infinity0
 */
public final class HeaderStreams {

  private HeaderStreams() {}

  /**
   * Create an {@link InputStream} that virtually prepends a header.
   *
   * <p>The returned stream first yields all bytes from {@code hd} and then yields bytes read from
   * the provided underlying stream {@code s}. The header array is not copied or modified.
   *
   * <p>Semantics of selected methods:
   *
   * <ul>
   *   <li>{@link InputStream#available()} returns the remaining header bytes plus the wrapped
   *       stream's available bytes.
   *   <li>{@link InputStream#skip(long)} consumes from the header first, then from the wrapped
   *       stream.
   *   <li>{@link InputStream#markSupported()} returns {@code false}; {@link InputStream#reset()}
   *       throws {@link IOException}.
   * </ul>
   *
   * <p>Preconditions: {@code hd} and {@code s} must be non-null. Behavior is undefined if either is
   * {@code null} (a {@link NullPointerException} may occur during use).
   *
   * <p>Thread-safety: not thread-safe.
   *
   * @param hd header bytes to expose before the underlying data; not modified
   * @param s underlying stream to read after the header
   * @return a stream that reads {@code hd} first, then {@code s}
   */
  public static InputStream augInput(final byte[] hd, InputStream s) {
    return new AugmentingHeaderInputStream(hd, s);
  }

  /**
   * Internal {@link FilterInputStream} that prepends a fixed header before data from the wrapped
   * stream.
   */
  private static final class AugmentingHeaderInputStream extends FilterInputStream {
    private final byte[] hd;
    // Index of the next byte to read from the header array.
    private int i = 0;

    AugmentingHeaderInputStream(byte[] hd, InputStream in) {
      super(in);
      this.hd = hd;
    }

    @Override
    public int available() throws IOException {
      return (hd.length - i) + in.available();
    }

    @Override
    public int read() throws IOException {
      return (i < hd.length) ? (hd[i++] & 0xff) : in.read();
    }

    @Override
    public int read(byte @NotNull [] buf, int off, int len) throws IOException {
      int prev = i;
      // Emit header bytes first.
      for (; i < hd.length && len > 0; i++, len--, off++) {
        buf[off] = hd[i];
      }
      int headerCount = i - prev;
      if (len == 0) {
        // Buffer filled entirely by header.
        return headerCount;
      }
      int n = in.read(buf, off, len);
      if (n == -1) {
        // Underlying stream is at EOF. If we produced any header bytes, report them; otherwise,
        // propagate EOF. This preserves the InputStream.read contract (never return 0 unless
        // len==0).
        return headerCount > 0 ? headerCount : -1;
      }
      return headerCount + n;
    }

    @Override
    public long skip(long len) throws IOException {
      // Per InputStream contract, negative or zero skip leaves the position unchanged and
      // returns 0.
      if (len <= 0) {
        return 0L;
      }
      int prev = i;
      long hdRemaining = hd.length - (long) i;
      long consume = Math.min(len, hdRemaining);
      if (consume > 0) {
        i += (int) consume;
        len -= consume;
      }
      long skipped = in.skip(len);
      return (i - prev) + skipped;
    }

    @Override
    public boolean markSupported() {
      // Mark/reset is intentionally unsupported to avoid tracking header state.
      return false;
    }

    @Override
    public void mark(int limit) {
      // No-op: mark/reset not supported.
    }

    @Override
    public void reset() throws IOException {
      // mark/reset not supported for this stream.
      throw new IOException("mark/reset not supported");
    }
  }

  /**
   * Create an {@link OutputStream} that enforces and swallows a required header.
   *
   * <p>The wrapper expects the first {@code hd.length} bytes written to match {@code hd}. Matching
   * bytes are not forwarded to the underlying stream. After the header is completely matched, all
   * subsequent bytes are forwarded unchanged to the wrapped stream.
   *
   * <p>If any of the first {@code hd.length} bytes differ from the expected header, the write
   * operation throws an {@link IOException} identifying the mismatching index and values. Close and
   * flush operations delegate to the wrapped stream. No final verification is performed at close
   * time; if fewer than {@code hd.length} bytes are written before closing, only the consumed
   * portion of the header is swallowed and nothing has been written to the underlying stream yet.
   *
   * <p>Preconditions: {@code hd} and {@code s} must be non-null.
   *
   * <p>Thread-safety: not thread-safe.
   *
   * @param hd expected header bytes; not modified
   * @param s underlying sink that receives data after the header is matched
   * @return a stream that discards the expected header and forwards subsequent bytes
   */
  public static OutputStream dimOutput(final byte[] hd, OutputStream s) {
    return new FilterOutputStream(s) {
      // Index of the next expected header byte.
      private int i = 0;

      @Override
      public void write(int b) throws IOException {
        if (i < hd.length) {
          if ((byte) b != hd[i]) {
            throw new IOException("byte " + i + ": expected '" + hd[i] + "'; got '" + b + "'.");
          }
          i++;
        } else {
          out.write(b);
        }
      }

      @Override
      public void write(byte @NotNull [] buf, int off, int len) throws IOException {
        for (; i < hd.length && len > 0; i++, len--, off++) {
          if (buf[off] != hd[i]) {
            throw new IOException(
                "byte " + i + ": expected '" + hd[i] + "'; got '" + buf[off] + "'.");
          }
        }
        out.write(buf, off, len);
      }
    };
  }
}
