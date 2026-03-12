package network.crypta.support.io;

import java.io.InputStream;
import org.jetbrains.annotations.NotNull;

/**
 * An {@link InputStream} that is always at end-of-file (EOF).
 *
 * <p>This stream never produces data and never blocks. Its behavior is useful when an API requires
 * a non-{@code null} {@code InputStream} but there is no data to read (for example, a missing or
 * intentionally empty resource).
 *
 * <p>Behavioral guarantees:
 *
 * <ul>
 *   <li>{@link #read()} always returns {@code -1}.
 *   <li>{@link #read(byte[], int, int)} returns {@code 0} when {@code len == 0}; otherwise it
 *       returns {@code -1}. When {@code -1} is returned, the destination buffer is not modified.
 *   <li>{@link #available()} (inherited) returns {@code 0}.
 *   <li>{@link #skip(long)} (inherited) returns {@code 0} for any value.
 *   <li>{@link #markSupported()} (inherited) returns {@code false}; {@link #reset()} (inherited)
 *       throws {@link java.io.IOException}.
 *   <li>{@link #transferTo(java.io.OutputStream)} (inherited) transfers {@code 0} bytes.
 * </ul>
 *
 * <p>The class is immutable, has no internal state, and does not hold external resources.
 * Concurrent calls do not share mutable state.
 */
public class NullInputStream extends InputStream {
  /**
   * Creates a new null input stream.
   *
   * <p>No resources are allocated; the stream has no state to initialize.
   */
  public NullInputStream() {
    // Intentionally empty: no state to initialize.
  }

  /**
   * Returns end-of-file immediately.
   *
   * @return always {@code -1}
   */
  @Override
  public int read() {
    return -1;
  }

  /**
   * Reads into a byte array; this stream is always at EOF.
   *
   * <p>When {@code len == 0}, returns {@code 0} as required by the {@link InputStream} contract.
   * For any positive {@code len}, returns {@code -1} without modifying {@code b}.
   *
   * @param b the destination buffer; must not be {@code null}
   * @param off the start offset in the buffer
   * @param len the maximum number of bytes to read
   * @return {@code 0} when {@code len == 0}; otherwise {@code -1}
   * @throws NullPointerException if {@code b} is {@code null}
   * @throws IndexOutOfBoundsException if {@code off} or {@code len} are negative, or if {@code off
   *     + len} exceeds {@code b.length}
   */
  @Override
  @SuppressWarnings({"java:S2583", "ConstantValue"})
  public int read(byte @NotNull [] b, int off, int len) {
    if (b == null) throw new NullPointerException("b");
    if (off < 0 || len < 0 || len > b.length - off) throw new IndexOutOfBoundsException();
    return (len == 0) ? 0 : -1;
  }
}
