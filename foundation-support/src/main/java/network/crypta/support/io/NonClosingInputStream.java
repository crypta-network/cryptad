package network.crypta.support.io;

import java.io.FilterInputStream;
import java.io.InputStream;

/**
 * InputStream wrapper whose {@link #close()} is a no-op, leaving the wrapped stream open.
 *
 * <p>This wrapper is useful in layered stream pipelines where an inner parser or decoder should be
 * closed for lifecycle symmetry, but the caller must retain ownership of the underlying input
 * channel. Typical examples include container or compression readers that should be disposed while
 * the original stream continues to carry additional framed data.
 *
 * <p>The class delegates all read operations to the wrapped stream via {@link FilterInputStream}
 * and only changes close semantics. Invoking {@link #close()} on this wrapper does not propagate a
 * physical close to the wrapped stream. As a result, resource release for the underlying stream
 * remains the responsibility of the code that created and owns that stream. This type is not
 * thread-safe beyond guarantees provided by the wrapped stream.
 */
@SuppressWarnings("java:S4929")
public class NonClosingInputStream extends FilterInputStream {

  /**
   * Creates a wrapper that delegates reads to {@code in} and suppresses close propagation.
   *
   * <p>The wrapper does not buffer, transform, or validate bytes by itself. It exists solely to
   * isolate close behavior so nested readers can be closed without transferring stream ownership.
   *
   * @param in source stream to wrap; it receives all delegated read operations unchanged.
   */
  public NonClosingInputStream(InputStream in) {
    super(in);
  }

  /**
   * Does not close the wrapped input stream.
   *
   * <p>This no-op implementation preserves caller ownership of the underlying stream so additional
   * bytes can be consumed after a nested component is closed. Code that owns the wrapped stream
   * must still close it explicitly when the full input lifecycle ends.
   */
  @Override
  public void close() {
    // Intentionally no-op: ownership of the underlying stream remains with the caller.
  }
}
