package network.crypta.store.alerts;

/**
 * Provides live, store-facing data for a maintenance progress alert.
 *
 * <p>Implementations expose a small, polling-friendly view of an in-flight store operation such as
 * a resize or rebuild. The values returned from this interface are intentionally presentation-free:
 * they identify the affected store, describe the kind of work in progress, and report progress
 * counters that the runtime can localize and render however it needs. This keeps formatting, HTML
 * generation, and runtime policy outside the store layer.
 *
 * <p>Callers should treat instances as dynamic and read-mostly. Repeated invocations may return
 * different values as maintenance proceeds, and {@link #isValid()} may switch from {@code true} to
 * {@code false} when the operation completes or is canceled.
 *
 * @see StoreAlertSink
 * @see StoreMaintenanceAlertKind
 */
public interface StoreMaintenanceAlertSource {
  /**
   * Returns a stable anchor string for this maintenance alert.
   *
   * <p>The anchor is used by runtime adapters as a durable identifier for deduplication, fragment
   * links, or UI element IDs. It should remain stable for the lifetime of the underlying
   * maintenance task and avoid characters that would be awkward in URLs or HTML identifiers.
   *
   * @return a short, stable identifier for the alert source that remains constant while the
   *     maintenance operation is active
   */
  String anchor();

  /**
   * Returns the human-readable name of the affected store.
   *
   * <p>This value is intended for interpolation into localized runtime messages. It should be
   * concise and recognizable to operators, for example, the configured datastore name or cache
   * label.
   *
   * @return store name suitable for operator-facing alert text and diagnostics
   */
  String storeName();

  /**
   * Returns the kind of maintenance task currently represented by this source.
   *
   * <p>Runtime adapters use this value to select the appropriate localization keys, severity, and
   * surrounding presentation. Implementations should return the same value throughout one logical
   * maintenance task.
   *
   * @return enum value describing whether the alert represents resize progress, rebuild progress,
   *     or another future maintenance category
   */
  StoreMaintenanceAlertKind kind();

  /**
   * Returns the amount of maintenance work completed so far.
   *
   * <p>The unit must match {@link #total()}. Implementations typically report processed slots,
   * entries, or similar work units. The value should be non-negative and usually monotonic while
   * the task is valid.
   *
   * @return completed work units for the current maintenance task, in the same units as {@link
   *     #total()}
   */
  long processed();

  /**
   * Returns the total amount of work expected for the maintenance task.
   *
   * <p>This provides the denominator for progress displays. Implementations should keep the unit
   * consistent with {@link #processed()}. The value may be zero when the total is unknown or when a
   * task has not started computing progress yet.
   *
   * @return total expected work units for the current task, using the same unit system as {@link
   *     #processed()}
   */
  long total();

  /**
   * Reports whether the task is rebuilding into the newer slot-filter format.
   *
   * <p>This flag lets the runtime choose between the legacy rebuild wording and the newer
   * conversion wording without forcing the store to produce preformatted strings. Callers should
   * interpret the flag only for rebuild-style alerts.
   *
   * @return {@code true} when the rebuild path is converting to the new slot-filter format; {@code
   *     false} for legacy rebuilds and non-rebuild tasks
   */
  boolean newSlotFilter();

  /**
   * Reports whether this alert source should still be shown.
   *
   * <p>Once this method returns {@code false}, runtime adapters should treat the maintenance alert
   * as finished or obsolete and stop presenting it. Implementations may return {@code false} when
   * the task completes, is canceled, or is replaced by a new source.
   *
   * @return {@code true} while the source represents an active maintenance condition; {@code false}
   *     when the alert should be considered stale or complete
   */
  boolean isValid();
}
