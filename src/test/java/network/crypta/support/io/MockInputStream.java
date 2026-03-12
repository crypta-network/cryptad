package network.crypta.support.io;

import java.io.InputStream;
import org.jspecify.annotations.NonNull;

/**
 * A minimal {@link InputStream} implementation for tests that require a predictable stub.
 *
 * <p>This class intentionally avoids any real backing store and instead provides fixed responses to
 * read operations. Use it when a test needs an {@code InputStream} instance for wiring or API
 * compatibility but does not care about actual data transfer, buffering, or end-of-stream
 * semantics. The behavior is deliberately simple and repeatable, which makes it suitable for
 * deterministic unit tests and for exercising call paths that should not perform real I/O.
 *
 * <p>Instances are stateless and do not mutate shared data. As implemented, repeated reads always
 * return the same values and do not advance any internal cursor. Because there is no mutable state,
 * instances are effectively thread-safe for concurrent use, though callers should still avoid
 * sharing streams across tests unless that is the intent.
 *
 * <ul>
 *   <li>Always signals end-of-stream for the single-byte {@link #read()} method.
 *   <li>Returns the requested length for bulk reads without modifying the buffer.
 * </ul>
 *
 * @see InputStream
 */
public class MockInputStream extends InputStream {

  /**
   * Creates a stateless mock stream with fixed read behavior.
   *
   * <p>The constructor performs no initialization because the stream does not maintain any internal
   * cursor or buffer. Constructing multiple instances yields identical behavior, and no external
   * resources are acquired or held. This makes construction inexpensive and safe to use in tight
   * unit-test loops.
   *
   * <pre>{@code
   * InputStream stream = new MockInputStream();
   * }</pre>
   */
  public MockInputStream() {
    // Intentionally empty: this mock has no state; read behavior is defined by overrides below.
  }

  /**
   * Returns an end-of-stream indicator for a single-byte read.
   *
   * <p>This mock does not model any real data source, so it always returns {@code -1} to indicate
   * end of stream. The method is idempotent and does not update any internal state. Use this
   * override to exercise call paths that check for end-of-stream without requiring real input.
   *
   * @return {@code -1} to indicate end-of-stream on every invocation.
   */
  @Override
  public int read() {
    return -1;
  }

  /**
   * Reports a successful bulk read without modifying the provided buffer.
   *
   * <p>The method returns {@code len} exactly as passed, without validating parameters or changing
   * the contents of {@code data}. This behavior is useful for tests that only verify the call path
   * or byte-count handling, not the actual bytes produced. Because no bytes are written, callers
   * should not assume that {@code data} contains any new values after the call.
   *
   * @param data destination buffer supplied by the caller; contents are left unchanged.
   * @param offset starting index into {@code data}; accepted as provided without validation.
   * @param len requested number of bytes to "read"; returned verbatim as the result.
   * @return the {@code len} argument, indicating a full-length read was reported.
   */
  @Override
  public int read(byte @NonNull [] data, int offset, int len) {
    return len;
  }
}
