package network.crypta.support.io;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.jetbrains.annotations.NotNull;

/**
 * OutputStream wrapper that flushes on close but does not close the wrapped stream.
 *
 * <p>This wrapper is intended for stream compositions where an inner layer must be closed to
 * finalize the protocol state, but ownership of the underlying destination remains with the caller.
 * Typical examples include checksum and compression streams that emit trailing bytes on close. In
 * such cases, closing the inner stream should flush bytes through the chain without closing the
 * final sink.
 *
 * <p>The class delegates all writes directly to the wrapped stream and changes only close
 * semantics. Calling {@link #close()} performs a flush and leaves the wrapped stream open for
 * further writes by outer code. This class has no internal synchronization and is mutable through
 * the wrapped stream state, so callers should apply external coordination when sharing instances
 * across threads.
 */
public class NonClosingOutputStream extends FilterOutputStream {

  /**
   * Creates a wrapper that forwards all writes to {@code out} and suppresses physical close.
   *
   * <p>The provided stream remains the owner of buffering and lifecycle behavior. This wrapper only
   * modifies how {@link #close()} behaves on this instance, allowing higher-level code to finalize
   * nested stream decorators without terminating the underlying destination channel.
   *
   * @param out destination stream that receives all forwarded bytes and flush operations.
   */
  public NonClosingOutputStream(OutputStream out) {
    super(out);
  }

  /**
   * Writes {@code len} bytes from {@code b}, starting at {@code off}, to the wrapped stream.
   *
   * <p>This override delegates directly to the underlying stream to preserve normal bulk-write
   * behavior and avoid {@link FilterOutputStream}'s byte-at-a-time fallback path. The method does
   * not add buffering or validation beyond what the wrapped stream already performs.
   *
   * @param b source byte array containing the data to write.
   * @param off zero-based index of the first byte to write from {@code b}.
   * @param len number of bytes to write from {@code b}.
   * @throws IOException if the wrapped stream rejects the writing or an I/O failure occurs.
   */
  @Override
  public void write(byte @NotNull [] b, int off, int len) throws IOException {
    out.write(b, off, len);
  }

  /**
   * Flushes the wrapped stream without closing it.
   *
   * <p>Use this to finalize nested stream decorators while preserving the caller's ability to keep
   * writing to the underlying destination. Any {@link IOException} thrown by the wrapped {@code
   * flush()} operation is propagated unchanged.
   *
   * @throws IOException if flushing the wrapped stream fails.
   */
  @Override
  public void close() throws IOException {
    out.flush();
  }
}
