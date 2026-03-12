package network.crypta.client;

import java.io.Serial;

/**
 * Exception indicating that required metadata references could not be resolved.
 *
 * <p>Parsers may successfully read a metadata structure while still leaving some referenced items
 * unresolved (for example, external keys, manifests, or chunks that are not yet available). This
 * checked exception communicates that follow-up work is needed before the requested operation can
 * complete. Callers typically catch this exception, inspect {@link #mustResolve}, and decide
 * whether to initiate additional fetches, defer the operation, or report a recoverable status to
 * the user.
 *
 * <p>Instances are immutable and safe to share between threads. The message should concisely
 * summarize the reason resolution failed or was deferred and may include contextual details such as
 * a high-level identifier. The design intentionally separates parse errors from resolution failures
 * to help distinguish malformed input ({@link MetadataParseException}) from missing dependencies.
 *
 * <ul>
 *   <li>Represents a recoverable, dependency-related failure during metadata handling.
 *   <li>Encourages callers to resolve listed prerequisites and retry the operation.
 *   <li>Does not include byte offsets or counts; include such context in the message if useful.
 * </ul>
 *
 * @see Metadata
 * @see MetadataParseException
 */
public class MetadataUnresolvedException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Array of metadata prerequisites that require resolution before continuing.
   *
   * <p>The array reference is final; callers should treat its contents as read-only for the
   * duration of error handling. Implementations may pass an empty or {@code null} array when no
   * specific items are known, in which case the message provides the best available context.
   */
  public final Metadata[] mustResolve;

  /**
   * Creates a new exception describing which metadata items must be resolved.
   *
   * <p>Construct this exception when resolution cannot proceed because one or more prerequisites
   * are missing or unavailable. The {@code mustResolve} array identifies items that, once retrieved
   * or computed, should allow the caller to retry. The message should remain concise and suitable
   * for logs or user-facing diagnostics.
   *
   * <pre>{@code
   * // Example: indicate unresolved dependencies prior to insertion
   * if (!dependenciesAvailable(meta)) {
   *   throw new MetadataUnresolvedException(meta.getMissing(), "Metadata dependencies unresolved");
   * }
   * }</pre>
   *
   * @param mustResolve array of metadata dependencies that require resolution; may be {@code null}
   *     or empty when specific items are unknown, and should be treated as read-only by callers.
   * @param message human-readable description summarizing why resolution failed or was deferred;
   *     must be non-null and concise enough for logs and error propagation.
   */
  public MetadataUnresolvedException(Metadata[] mustResolve, String message) {
    super(message);
    this.mustResolve = mustResolve;
  }
}
