package network.crypta.support.math;

/**
 * Receives notifications when support-side time checks detect a local clock skew.
 *
 * <p>This interface defines the narrow contract that support-layer components use when they need to
 * surface a user-visible time-skew condition without depending on node-specific alerting code. In
 * practice, callers such as {@code TimeDecayingRunningAverage} invoke it after detecting wall-clock
 * or uptime regressions while continuing their monotonic-time calculations. That keeps timing math
 * isolated from presentation concerns while still giving higher layers a clear place to register
 * operator-facing alerts.
 *
 * <p>Implementations may map the notification to a UI banner, a persistent user alert, or another
 * operator-facing mechanism. Callers may invoke the callback from non-UI threads and may notify
 * more than once if skew is detected repeatedly, so implementations should return quickly and
 * perform any deduplication or thread marshaling they require.
 */
public interface TimeSkewAlertCallback {

  /**
   * Requests an operator-visible alert for a detected local time-skew condition.
   *
   * <p>Callers use this after they have already determined that the local wall clock moved backward
   * or otherwise became inconsistent with elapsed monotonic time. The callback is
   * notification-only: it does not influence the caller's timing calculations, and it does not
   * imply that the condition has cleared. Implementations may schedule UI work or alert
   * registration, but they should keep the call itself lightweight so reporting paths remain
   * responsive.
   */
  void setTimeSkewDetectedUserAlert();
}
