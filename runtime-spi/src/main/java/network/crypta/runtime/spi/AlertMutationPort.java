package network.crypta.runtime.spi;

/**
 * Detached mutation surface for alert dismissal.
 *
 * <p>This port keeps alert-changing operations separate from the read-only snapshot surface. It is
 * intentionally limited to the smallest mutation needed by the current Platform API and shell work:
 * dismissing one alert by the detached identifier previously exposed in an {@link AlertSnapshot}.
 * Implementations remain responsible for any runtime-side side effects such as unregistering the
 * alert, marking it invalid, or triggering cleanup work.
 */
public interface AlertMutationPort {
  /**
   * Dismisses the alert identified by the supplied id.
   *
   * <p>The identifier must be one that was previously exposed through the detached alert feed. The
   * interface does not require implementations to report missing or non-dismissible alerts as
   * separate errors; callers should treat the operation as a runtime-defined best-effort mutation.
   *
   * @param alertId alert identifier previously exposed in a detached snapshot
   */
  void dismiss(int alertId);
}
