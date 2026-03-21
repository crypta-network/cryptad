package network.crypta.support.io;

import java.io.BufferedReader;

/**
 * Factory utilities that adapt common sources to the {@link LineReader} abstraction.
 *
 * <p>The methods in this class create minimal, stateful adapters so callers can consume text lines
 * through a uniform {@link LineReader} API. The adapters intentionally ignore the {@code
 * maxLength}, {@code bufferSize}, and {@code utf} parameters of {@link LineReader#readLine(int,
 * int, boolean)}; those values are accepted to satisfy the interface but are not enforced by these
 * particular implementations.
 *
 * <p>Thread-safety: returned adapters are not thread-safe. They maintain internal iteration state
 * and/or share the provided backing object. Synchronize externally if accessed from multiple
 * threads.
 *
 * <p>Nullability: method parameters must be non-{@code null}. Passing {@code null} will cause a
 * {@link NullPointerException} when the returned adapter is used.
 */
public final class Readers {

  private Readers() {}

  /**
   * Returns a {@link LineReader} that delegates to the given {@link BufferedReader}.
   *
   * <p>Each invocation of {@link LineReader#readLine(int, int, boolean)} forwards to {@link
   * BufferedReader#readLine()} exactly once and returns its result. The {@code maxLength}, {@code
   * bufferSize}, and {@code utf} parameters are ignored by this adapter.
   *
   * <p>End-of-input is signaled by returning {@code null} when the underlying reader returns {@code
   * null}. The adapter advances the supplied {@code BufferedReader}; callers must not reuse the
   * same reader concurrently elsewhere.
   *
   * <p>Preconditions: {@code br} must be non-{@code null}. If {@code null} is provided, a {@link
   * NullPointerException} will be thrown upon first use of the returned adapter. Any {@link
   * java.io.IOException} thrown by {@code br.readLine()} propagates from the adapter.
   *
   * @param br the backing {@code BufferedReader}; must be non-{@code null}.
   * @return a stateful adapter that reads from {@code br}.
   */
  public static LineReader fromBufferedReader(final BufferedReader br) {
    return (maxLength, bufferSize, utf) -> br.readLine();
  }

  /**
   * Returns a {@link LineReader} that iterates over the provided {@link String} array.
   *
   * <p>Each call to {@link LineReader#readLine(int, int, boolean)} returns the next array element.
   * After the last element is returned, subsequent calls yield {@code null}. The {@code maxLength},
   * {@code bufferSize}, and {@code utf} parameters are ignored by this adapter.
   *
   * <p>Elements should be non-{@code null}. If a {@code null} entry is present, the adapter returns
   * {@code null} for that call (indistinguishable from end-of-input for that call) and then
   * continues with the remaining entries on subsequent calls.
   *
   * <p>Preconditions: {@code lines} must be non-{@code null}. If {@code null} is provided, a {@link
   * NullPointerException} will be thrown upon first use of the returned adapter.
   *
   * @param lines the sequence of lines to expose; must be non-{@code null}.
   * @return a stateful adapter over {@code lines}.
   */
  public static LineReader fromStringArray(final String[] lines) {
    return new LineReader() {
      // Index of the last returned element; starts before the first element.
      private int currentLine = -1;

      @Override
      public String readLine(int maxLength, int bufferSize, boolean utf) {
        // Advance to the next element and return it if available; otherwise signal end-of-input.
        if (++currentLine < lines.length) {
          return lines[currentLine];
        }
        return null;
      }
    };
  }
}
