package network.crypta.support;

import java.io.Serial;

/**
 * Exception type optimized for control flow with minimal overhead.
 *
 * <p>Instances of this class are intended to be thrown and caught in situations where an
 * exceptional path is expected and frequent (e.g., short-circuiting out of deep logic) rather than
 * to report programmer errors. By default, it does not capture a stack trace, which avoids the cost
 * of walking the stack and allocating frame elements.
 *
 * <p>Subclasses may temporarily opt in to full diagnostics by overriding {@link
 * #shouldFillInStackTrace()} to return {@code true}. When disabled (the default), printing or
 * logging typically shows only the exception type and message without stack frames.
 *
 * <p>Thread-safety: {@link #fillInStackTrace()} is declared {@code synchronized} to match the
 * contract of {@link Throwable#fillInStackTrace()} and to satisfy static analyzers that require the
 * same synchronization modifier as the parent implementation.
 *
 * @see #shouldFillInStackTrace()
 * @see Throwable#fillInStackTrace()
 * @see <a
 *     href="https://blogs.oracle.com/jrose/entry/longjumps_considered_inexpensive">Optimization:
 *     Longjumps Considered Inexpensive</a>
 * @author bertm
 */
public class LightweightException extends Exception {
  // Stable serialization identifier; keeps compatibility across versions.
  @Serial private static final long serialVersionUID = -1;

  /** Constructs a new instance with no detail message and, by default, no captured stack trace. */
  public LightweightException() {
    super();
  }

  /**
   * Constructs a new instance with the specified detail message and, by default, no captured stack
   * trace.
   *
   * @param message human-readable detail; may be {@code null}.
   */
  public LightweightException(String message) {
    super(message);
  }

  /**
   * Constructs a new instance with the specified cause and, by default, no captured stack trace.
   *
   * @param cause the underlying cause; may be {@code null}.
   */
  public LightweightException(Throwable cause) {
    super(cause);
  }

  /**
   * Constructs a new instance with the specified message and cause and, by default, no captured
   * stack trace.
   *
   * @param message human-readable detail; may be {@code null}.
   * @param cause the underlying cause; may be {@code null}.
   */
  public LightweightException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Indicates whether this instance should capture a stack trace when thrown.
   *
   * <p>The default implementation returns {@code false} to preserve the lightweight behavior of
   * this class. Subclasses may override to return {@code true} when diagnostics are needed.
   *
   * @return {@code true} to enable stack trace capture; {@code false} to disable it.
   */
  protected boolean shouldFillInStackTrace() {
    return false;
  }

  /**
   * Conditionally fills in the execution stack trace based on {@link #shouldFillInStackTrace()}.
   *
   * <p>When tracing is enabled, delegates to {@code super.fillInStackTrace()} and returns its
   * result (typically {@code this}). When disabled, performs no work and deliberately returns
   * {@code null} to minimize overhead.
   *
   * <p>Threading: declared {@code synchronized} to match {@link Throwable#fillInStackTrace()}.
   *
   * @return {@code null} when stack trace capture is disabled; otherwise the value returned by the
   *     superclass implementation.
   */
  @Override
  public final synchronized Throwable fillInStackTrace() {
    if (shouldFillInStackTrace()) {
      return super.fillInStackTrace();
    }
    // Intentionally return null to signal "no stack trace" and avoid allocation work.
    return null;
  }
}
