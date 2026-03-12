package network.crypta.support.io;

import java.io.Serial;

/**
 * Signals that resuming a previously persisted or paused I/O resource failed.
 *
 * <p>This checked exception is used by I/O abstractions in this package (for example, buckets and
 * random-access buffers) when reloading on-disk state or reconstructing in-memory structures from
 * persistent metadata does not succeed. Typical causes include missing files, mismatched or
 * truncated lengths, or corruption detected during format checks. Callers should treat this as a
 * failure of the specific artifact being resumed and decide whether to recreate it or abandon the
 * operation depending on context.
 */
public class ResumeFailedException extends Exception {
  /** Serialization version for compatibility across releases. */
  @Serial private static final long serialVersionUID = 4332224721883071870L;

  /**
   * Creates an exception with a detail message describing the resume failure.
   *
   * @param message human-readable description of why resuming failed; may be {@code null}.
   */
  public ResumeFailedException(String message) {
    super(message);
  }

  /**
   * Creates an exception that wraps an underlying cause.
   *
   * <p>The detail message is set to {@code cause.toString()} and the cause is attached using {@link
   * Throwable#initCause(Throwable)} so the original stack trace is preserved.
   *
   * @param e non-{@code null} cause of the resume failure.
   * @throws NullPointerException if {@code e} is {@code null} (due to {@code e.toString()}).
   */
  // Use cause.toString() for the message and attach the cause to preserve its stack trace.
  public ResumeFailedException(Throwable e) {
    super(e.toString());
    this.initCause(e);
  }
}
