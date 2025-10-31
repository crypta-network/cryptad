package network.crypta.node;

/**
 * Callback interface for reporting detected local clock skew.
 *
 * <p>Implementations surface a user-facing alert when the system clock appears out of sync. The
 * exact presentation is application-specific (for example, UI banner, status panel entry, or a
 * prominent log message). Callers may invoke this callback from non-UI threads; implementations
 * that interact with UI toolkits must marshal to the appropriate thread.
 *
 * <p>This interface does not prescribe how often the alert is shown. Implementations should avoid
 * repeatedly notifying the user if the condition persists.
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public interface TimeSkewDetectorCallback {

  /**
   * Requests that the implementation present a user-visible alert indicating that time skew has
   * been detected.
   *
   * <p>Side effects depend on the concrete implementation. The call should return promptly; any
   * long-running work or UI updates should be scheduled asynchronously.
   */
  void setTimeSkewDetectedUserAlert();
}
