package network.crypta.node.stats;

import java.io.Serial;

/**
 * Signals that node or store statistics are not currently available to be read.
 *
 * <p>This checked exception communicates that a statistics provider cannot fulfill a request at
 * this time. Typical reasons include a store that is still initializing, a component that has been
 * shut down, metrics that are disabled by configuration, or a data source that is temporarily
 * inaccessible. Throwing an explicit exception is preferred over returning partial data because it
 * forces callers to handle the absence of metrics explicitly and avoids conflating "zero" with
 * "unknown".
 *
 * <p>The class is immutable and thread-safe. Instances may carry a human-readable message and/or a
 * cause describing the underlying condition; callers should not rely on specific message wording as
 * part of control flow. In boundary layers (e.g., HTTP endpoints or CLI tools) consider translating
 * this exception into a transient failure status so that users understand that the system remains
 * functional but cannot report statistics yet.
 *
 * <ul>
 *   <li>Startup/shutdown windows when stores are not initialized or are being torn down.
 *   <li>Metrics collection explicitly disabled or not compiled into the current build profile.
 *   <li>Access restrictions in sandboxed environments that block probing or file access.
 *   <li>Plugin-provided statistics while the plugin is missing, disabled, or reloading.
 * </ul>
 *
 * @author nikotyan
 */
@SuppressWarnings("unused")
public class StatsNotAvailableException extends Exception {

  /** Serialization identifier for stable exception transport and persistence compatibility. */
  @Serial private static final long serialVersionUID = -7349859507599514672L;

  /**
   * Creates an exception with no detail message or cause.
   *
   * <p>Use this constructor when the absence of statistics is expected and no further context is
   * necessary. Downstream handlers may convert this into a generic "stats unavailable" response or
   * retry later depending on the calling policy.
   */
  public StatsNotAvailableException() {}

  /**
   * Creates an exception with a human-readable message.
   *
   * <p>The message should describe the observed condition succinctly (for example, {@code "Store
   * still initializing"}). Do not depend on the exact text for control flow; treat it as diagnostic
   * information for logs and user-facing messages.
   *
   * @param s detail message explaining why statistics cannot be provided; may be {@code null} when
   *     the reason is implicit or obvious from context.
   */
  public StatsNotAvailableException(String s) {
    super(s);
  }

  /**
   * Creates an exception with a message and an underlying cause.
   *
   * <p>Use this when the unavailability stems from another failure (I/O, permissions, lifecycle
   * state). The cause is preserved and accessible via {@link Throwable#getCause()} for diagnostics
   * and logging.
   *
   * @param s detail message describing the high-level condition; may be {@code null} if the cause
   *     is descriptive enough on its own.
   * @param throwable the underlying cause that prevented providing statistics; may be {@code null}
   *     if unknown or not applicable.
   */
  public StatsNotAvailableException(String s, Throwable throwable) {
    super(s, throwable);
  }

  /**
   * Creates an exception that wraps an underlying cause with no standalone message.
   *
   * <p>This is useful when the cause already carries a clear explanation. Callers should still
   * avoid treating specific exception types as stable interfaces and prefer coarse-grained handling
   * at higher layers.
   *
   * @param throwable the underlying cause indicating why statistics are unavailable; may be {@code
   *     null} to indicate the reason is unspecified.
   */
  public StatsNotAvailableException(Throwable throwable) {
    super(throwable);
  }
}
