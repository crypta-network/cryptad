package network.crypta.support.io;

import java.io.IOException;
import java.io.Writer;

/**
 * A {@link Writer} that silently discards all characters written to it.
 *
 * <p>Use this when output must be explicitly ignored (for example, in tests, optional logging, or
 * piping an API that requires a {@code Writer} but does not need the result). It behaves like a
 * "null sink": all write operations are ignored, and there is nothing to flush or close.
 *
 * <p>Concurrency: this class maintains no mutable state. Calls from multiple threads do not
 * interact. The {@link Writer} base type does not guarantee thread-safety, so callers should still
 * apply external synchronization when they require strict ordering with other I/O operations.
 */
public class NullWriter extends Writer {

  /**
   * Discards the specified range of characters.
   *
   * <p>This implementation does not validate arguments and never throws an {@link IOException}.
   * Passing {@code null} for {@code cbuf} or out-of-bounds {@code off} or {@code len} has no
   * effect. No data is stored or emitted.
   *
   * @param cbuf the character buffer (ignored; may be {@code null})
   * @param off start offset in {@code cbuf} (ignored)
   * @param len number of characters to write (ignored)
   * @throws IOException never thrown by this implementation
   */
  @SuppressWarnings("NullableProblems")
  @Override
  public void write(char[] cbuf, int off, int len) throws IOException {
    // Intentionally no-op: discard input without validation or allocation.
  }

  /**
   * Performs no operation.
   *
   * <p>There is no buffered state to flush.
   *
   * @throws IOException never thrown by this implementation
   */
  @Override
  public void flush() throws IOException {
    // Intentionally no-op: nothing is buffered.
  }

  /**
   * Performs no operation and may be called multiple times safely.
   *
   * <p>There are no resources to release; the method is idempotent.
   *
   * @throws IOException never thrown by this implementation
   */
  @Override
  public void close() throws IOException {
    // Intentionally no-op: no resources to release; idempotent.
  }
}
