package network.crypta.client.async.alerts;

/**
 * Receives client-layer alerts and hands them to the owning alert subsystem.
 *
 * <p>This is the active half of the client-owned seam. Client code depends on this interface, so it
 * can emit operator-visible notifications without importing runtime-specific alert managers or UI
 * types. Implementations decide how alerts are validated, queued, or translated before they reach
 * the concrete alert system.
 *
 * <p>Callers typically get a sink during startup wiring and reuse it for the lifetime of a {@code
 * ClientContext}. Implementations may forward immediately, buffer briefly, or reject alert types
 * they do not understand. The contract is intentionally small so the client layer stays decoupled
 * from alert rendering concerns.
 */
@FunctionalInterface
public interface ClientAlertSink {

  /**
   * Posts an alert to the owning alert system.
   *
   * <p>Implementations should treat this as a handoff point rather than a request to render the
   * alert directly. The sink may forward immediately, enqueue the alert for later processing, or
   * reject values that do not belong to the concrete alert model behind the seam.
   *
   * @param alert alert emitted from client-layer code and ready for sink-specific handling
   */
  void post(ClientAlert alert);
}
