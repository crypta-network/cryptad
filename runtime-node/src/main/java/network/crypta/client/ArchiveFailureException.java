package network.crypta.client;

import java.io.Serial;

/**
 * Exception thrown to indicate that a client archive operation failed.
 *
 * <p>This checked exception is used by client-side archive handling code to signal unrecoverable
 * conditions such as excessive nesting or structural loops found while processing an archive.
 * Callers typically encounter it while creating, traversing, or extracting archive contents and
 * should either handle the failure locally (e.g., prompt the user, fall back, or skip the offending
 * entry) or propagate it to a higher-level error handler.
 *
 * <p>The type is immutable and thread-safe; once constructed it carries a stable message and,
 * optionally, a root cause. The public constants {@link #TOO_MANY_LEVELS} and {@link
 * #ARCHIVE_LOOP_DETECTED} provide canonical messages for common failure modes so that diagnostics
 * remain consistent across the codebase. Implementations are encouraged to reuse these constants
 * when throwing the exception.
 *
 * <ul>
 *   <li>Checked exception: callers must catch or declare it.
 *   <li>Immutable: safe to share across threads after creation.
 *   <li>Messages are intended for logs; they are not localized.
 * </ul>
 *
 * @author amphibian (Matthew Toseland)
 */
public class ArchiveFailureException extends Exception {

  @Serial private static final long serialVersionUID = -5915105120222575469L;

  /**
   * Canonical message used when the archive depth exceeds the permitted nesting level. The value is
   * stable and suitable for programmatic comparisons, log records, or metrics labeling. It is not
   * localized and should not be displayed directly to end users without appropriate wrapping.
   */
  public static final String TOO_MANY_LEVELS = "Too many archive levels";

  /**
   * Canonical message used when a structural loop is detected while traversing an archive (for
   * example, a cycle via recursive references). The value is stable and intended for diagnostics;
   * it is not localized and should be wrapped before being presented in user interfaces.
   */
  public static final String ARCHIVE_LOOP_DETECTED = "Archive loop detected";

  /**
   * Create a new exception with a descriptive message.
   *
   * <p>Use this constructor when there is no underlying {@code Throwable} available or when the
   * cause adds no additional value beyond the provided message. Prefer the canonical constants
   * {@link #TOO_MANY_LEVELS} and {@link #ARCHIVE_LOOP_DETECTED} for common failure modes to keep
   * logs and metrics consistent across components.
   *
   * @param message human-readable description of the failure condition; may include context such as
   *     entry names or depth values. Not localized by default and typically intended for logs
   *     rather than direct UI display.
   */
  public ArchiveFailureException(String message) {
    super(message);
  }

  /**
   * Create a new exception with a message and an underlying cause.
   *
   * <p>Use this constructor when a lower-level error triggered the archive failure and preserving
   * the original exception improves diagnosability. The cause is attached via {@link
   * Throwable#initCause(Throwable)} and can be retrieved with {@link Throwable#getCause()}.
   *
   * @param message human-readable description of the failure condition; should summarize the
   *     outcome at the archive layer. Not localized by default and primarily intended for
   *     diagnostic logs.
   * @param e the root cause that led to the failure; may be {@code null} when no specific
   *     underlying exception exists, or it is unavailable.
   */
  public ArchiveFailureException(String message, Exception e) {
    super(message);
    initCause(e);
  }
}
