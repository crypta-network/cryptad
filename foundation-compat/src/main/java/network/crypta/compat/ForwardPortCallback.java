package network.crypta.compat;

import java.util.Map;

/**
 * Receives asynchronous compatibility-layer updates for port-forwarding outcomes.
 *
 * <p>Implementations are notified when a forwarding provider has new status information for one or
 * more previously requested public ports. The callback is intentionally batch-oriented so providers
 * can report partial or complete updates in a single invocation, reducing coordination overhead.
 * Callers should tolerate repeated notifications, out-of-order updates, and mixed success/failure
 * states across entries.
 *
 * <p>Threading is provider-defined: callbacks may arrive on worker threads or scheduling executors.
 * Implementations should keep processing non-blocking and thread-safe, delegating expensive work as
 * needed.
 *
 * <ul>
 *   <li><b>Input model:</b> map keyed by requested {@link ForwardPort} values.
 *   <li><b>Output model:</b> no return value; consumers update local state or alerts.
 * </ul>
 */
public interface ForwardPortCallback {
  /**
   * Applies the latest forwarding status observations for one or more requested ports.
   *
   * <p>The provided map associates each requested port descriptor with a status snapshot describing
   * current forwarding confidence and optional diagnostic reason text. The map may be empty when no
   * actionable updates are available. Implementations should treat absent keys as unchanged rather
   * than implicitly failed.
   *
   * @param statuses latest known status entries keyed by requested forwarded ports
   */
  void portForwardStatus(Map<ForwardPort, ForwardPortStatus> statuses);
}
