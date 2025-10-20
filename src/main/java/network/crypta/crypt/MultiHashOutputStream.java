package network.crypta.crypt;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.jetbrains.annotations.NotNull;

/**
 * An {@link OutputStream} that forwards all writes to a wrapped stream while computing multiple
 * hash digests in parallel.
 *
 * <p>Each call to {@code write(...)} is passed through to the underlying {@link OutputStream} and
 * the same bytes are fed into a {@link MultiHashDigester}. Use {@link #getResults()} to obtain the
 * current digest values for all configured algorithms.
 *
 * <p>Thread safety: instances are not thread-safe. External synchronization is required when
 * accessed concurrently.
 *
 * <p>Flush/close semantics follow {@link FilterOutputStream}: {@code flush()} and {@code close()}
 * are delegated to the wrapped stream.
 */
public class MultiHashOutputStream extends FilterOutputStream {

  private final MultiHashDigester digester;

  /**
   * Creates a new stream that computes a set of digests selected by a bit mask while writing to the
   * given {@code proxy} stream.
   *
   * <p>The {@code generateHashes} mask is interpreted by {@link
   * MultiHashDigester#fromBitmask(long)} to choose the hash algorithms to compute.
   *
   * @param proxy the destination stream to which all bytes are written
   * @param generateHashes bit mask selecting which hashes to compute
   */
  public MultiHashOutputStream(OutputStream proxy, long generateHashes) {
    super(proxy);
    this.digester = MultiHashDigester.fromBitmask(generateHashes);
  }

  /**
   * Writes one byte to the underlying stream and updates all active hash digests with the same
   * value.
   *
   * @param b the byte value to write; only the low-order eight bits are used
   * @throws IOException if the underlying stream throws an I/O error
   */
  @Override
  public void write(int b) throws IOException {
    out.write(b);
    digester.update(new byte[] {(byte) b}, 0, 1);
  }

  /**
   * Writes {@code len} bytes starting at {@code off} from {@code buf} to the underlying stream and
   * updates all active hash digests with the same range.
   *
   * <p>Preconditions mirror {@link OutputStream#write(byte[], int, int)}: {@code buf} must not be
   * {@code null}; {@code off} and {@code len} must specify a valid subrange of {@code buf}.
   *
   * @param buf the source buffer (non-null)
   * @param off the start offset within the buffer
   * @param len the number of bytes to write
   * @throws IOException if the underlying stream throws an I/O error
   */
  @Override
  public void write(byte @NotNull [] buf, int off, int len) throws IOException {
    out.write(buf, off, len);
    digester.update(buf, off, len);
  }

  /**
   * Returns the current digest results for all configured algorithms.
   *
   * <p>The returned array is a snapshot and modifications to it do not affect this stream. The
   * order and contents of the results are defined by the associated {@link MultiHashDigester}.
   *
   * @return an array of computed {@link HashResult} values
   */
  public HashResult[] getResults() {
    return digester.getResults().toArray(new HashResult[0]);
  }
}
