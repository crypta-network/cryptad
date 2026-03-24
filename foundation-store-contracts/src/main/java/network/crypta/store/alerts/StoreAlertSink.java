package network.crypta.store.alerts;

/**
 * Receives dynamic store-maintenance alert sources published by store implementations.
 *
 * <p>This interface is the narrow boundary between the leaf-owned store layer and the root-owned
 * runtime alert system. Stores do not format text, localize strings, or build UI fragments.
 * Instead, they register a live {@link StoreMaintenanceAlertSource} and allow the runtime layer to
 * decide whether that source becomes a user alert, log entry, diagnostics panel, or no visible
 * output at all.
 *
 * <p>The contract is intentionally small so the store layer can remain reusable and testable. A
 * sink implementation may keep the source for repeated polling, transform it into another alert
 * representation, or ignore it completely when the current runtime does not expose maintenance
 * alerts.
 *
 * @see StoreMaintenanceAlertSource
 */
public interface StoreAlertSink {
  /**
   * Sink that silently drops all registrations.
   *
   * <p>Use this when a caller wants to avoid null checks but has no alert destination for store
   * maintenance progress.
   */
  StoreAlertSink NO_OP = _ -> {};

  /**
   * Registers a store-maintenance alert source with this sink.
   *
   * <p>The source is expected to remain dynamic after registration. Implementations may poll it
   * repeatedly, snapshot it immediately, or decide not to surface it. Callers should typically
   * register long-lived sources once rather than creating new source objects for every progress
   * update.
   *
   * @param alert live source describing a maintenance operation and its current progress; sink
   *     implementations may ignore it when the runtime does not expose alerts
   */
  void register(StoreMaintenanceAlertSource alert);
}
