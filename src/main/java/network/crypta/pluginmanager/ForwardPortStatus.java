package network.crypta.pluginmanager;

/**
 * Immutable value object describing the outcome of a plugin-managed port-forwarding attempt.
 *
 * <p>Plugins that interact with a router, firewall, or other gateway can use this type to report
 * whether an external port mapping was established, whether the result is merely optimistic, or
 * whether the attempt is still ongoing. Consumers typically interpret {@link #status} using the
 * provided integer constants (for example {@link #IN_PROGRESS} or {@link #DEFINITE_FAILURE}) and
 * optionally surface {@link #reasonString} to operators for diagnostics.
 *
 * <p>This class is intentionally small and allocation-friendly. It does not enforce that {@link
 * #status} matches one of the predefined constants; callers should treat unknown values as
 * plugin-specific and handle them conservatively. Instances are fully immutable and therefore
 * thread-safe to publish and share between threads.
 */
public class ForwardPortStatus {

  /**
   * Numeric status code describing the port-forwarding state or outcome.
   *
   * <p>Callers generally treat this as an ordinal-like value where larger numbers are more
   * confident success states and negative numbers represent failures. The recommended values are
   * the constants defined on this class (for example {@link #MAYBE_SUCCESS} and {@link
   * #PROBABLE_FAILURE}).
   */
  public final int status;

  /**
   * The port forward definitely succeeded.
   *
   * <p>This indicates that the plugin has strong evidence the mapping is in place (for example via
   * a successful verification step). Consumers can treat this as a confirmed "open" state and may
   * reduce or skip out-of-band re-checks.
   */
  public static final int DEFINITE_SUCCESS = 3;

  /**
   * The port forward probably succeeded. I.e. it succeeded unless there was for example hostile
   * action on the part of the router.
   *
   * <p>This value communicates that the plugin received a plausible success response but cannot
   * guarantee that the mapping is actually reachable from the public Internet. Callers typically
   * treat this as "likely open" while still allowing a later confirmation probe when reliable
   * reachability matters.
   */
  public static final int PROBABLE_SUCCESS = 2;

  /**
   * The port forward may have succeeded. Or it may not have. We should definitely try to check out
   * of band. See {@code UP&P}: Many routers say they've forwarded the port when they haven't.
   *
   * <p>This state exists for environments where the router response is known to be unreliable or
   * ambiguous. Consumers should assume the port is not forwarded until a separate, independent
   * verification indicates otherwise, while still preserving the possibility that the mapping does
   * work.
   */
  public static final int MAYBE_SUCCESS = 1;

  /**
   * The port forward is in progress.
   *
   * <p>The plugin has started an attempt but cannot yet provide a stable success or failure
   * conclusion. Callers may keep polling, subscribe to plugin events, or continue operating in a
   * fallback mode until the status transitions to a non-zero terminal value.
   */
  public static final int IN_PROGRESS = 0;

  /**
   * The port forward probably failed.
   *
   * <p>This indicates a failure that is not fully proven to be permanent, such as a transient
   * error, a timeout, or an uncertain router response. Callers can treat this as "not forwarded"
   * while still allowing retries or secondary verification depending on their policy.
   */
  public static final int PROBABLE_FAILURE = -1;

  /**
   * The port forward definitely failed.
   *
   * <p>This indicates a definitive failure such as an explicit refusal, an unrecoverable
   * configuration problem, or a completed attempt that did not produce a usable mapping.
   */
  public static final int DEFINITE_FAILURE = -2;

  /**
   * Optional, human-readable explanation associated with the {@link #status}.
   *
   * <p>This value is intended for diagnostics and UI surfaces; it is not required to be stable or
   * machine-parseable. Implementations may leave it {@code null} when no explanation is available.
   */
  public final String reasonString;

  /**
   * External port number reported by the plugin, if applicable.
   *
   * <p>Some port-forwarding mechanisms may allocate an external port that differs from the
   * originally requested port. When that happens, plugins can return the externally mapped port
   * here so the node can advertise or probe the correct endpoint. The interpretation of
   * "unspecified" is plugin-dependent.
   */
  public final int externalPort;

  /**
   * Creates a new status report for a port-forwarding attempt.
   *
   * <p>The provided {@code status} should normally be one of the predefined constants on this
   * class, but this constructor intentionally does not validate inputs so that plugins can express
   * additional states if needed. {@code reason} is carried verbatim and is intended for operators,
   * logs, or UI; it should not be relied upon for program logic. {@code externalPort} can be used
   * to surface the externally mapped port when it differs from an internal/listening port.
   *
   * @param status numeric status code, typically one of the {@code *_SUCCESS}/{@code *_FAILURE}
   *     constants or {@link #IN_PROGRESS}
   * @param reason human-readable explanation for the status, or {@code null} when unavailable
   * @param externalPort externally mapped port number reported by the plugin, if applicable
   */
  public ForwardPortStatus(int status, String reason, int externalPort) {
    this.status = status;
    this.reasonString = reason;
    this.externalPort = externalPort;
  }
}
