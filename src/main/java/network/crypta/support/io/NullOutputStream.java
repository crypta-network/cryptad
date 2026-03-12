package network.crypta.support.io;

import java.io.OutputStream;

/**
 * An {@link OutputStream} that silently discards all bytes written to it.
 *
 * <p>Purpose: provide a no-op sink analogous to {@code /dev/null}. This is useful in tests,
 * benchmarks, or code paths that require a non-null {@code OutputStream} but where the produced
 * bytes are not needed.
 *
 * <p>Behavior: - {@link #write(int)} and {@link #write(byte[], int, int)} return immediately and do
 * nothing. - {@link #flush()} and {@link #close()} are inherited from {@link OutputStream} and have
 * no effect for this implementation. - {@link #write(byte[])} is intentionally not overridden so
 * that passing a {@code null} array triggers the standard {@link NullPointerException} from {@link
 * OutputStream#write(byte[])}. A non-null array delegates to {@link #write(byte[], int, int)} and
 * is therefore ignored.
 *
 * <p>Thread-safety: this class is stateless and has no side effects; it is safe to use from
 * multiple threads concurrently.
 *
 * <p>Complexity: all operations are O(1) and perform no allocation.
 */
public class NullOutputStream extends OutputStream {

  /**
   * Discards a single byte.
   *
   * @param b the byte value; the value is ignored
   */
  @Override
  public void write(int b) {
    // Intentionally no-op: discard one byte
  }

  /**
   * Discards a byte range from the provided array.
   *
   * <p>The parameters are not validated and the contents are not inspected. The call has no
   * observable effect.
   *
   * @param buf the source buffer; the reference is not dereferenced by this implementation
   * @param off the starting offset in the array; ignored
   * @param len the number of bytes to write; ignored
   */
  @Override
  @SuppressWarnings("NullableProblems") // The parameters are not validated
  public void write(byte[] buf, int off, int len) {
    // Intentionally no-op: discard the specified range
  }
}
