package network.crypta.store.alerts;

/**
 * Lists the maintenance progress categories that stores can expose through the alert SPI.
 *
 * <p>Runtime adapters use these values to pick localization keys and presentation details while the
 * store layer remains free of user-interface code. The enum is intentionally small because the
 * current boundary only needs to describe long-running resize and rebuild work.
 */
public enum StoreMaintenanceAlertKind {
  /**
   * Progress for a store resize operation that changes the effective capacity of the datastore.
   *
   * <p>Typical runtimes present this as an operator-visible task because resizing can run for an
   * extended period and may temporarily reduce performance.
   */
  RESIZE_PROGRESS,

  /**
   * Progress for a store rebuild or maintenance pass over existing store data.
   *
   * <p>This covers both legacy slot-filter rebuilds after an unclean shutdown and rebuilds that
   * convert data into a newer maintenance format.
   */
  REBUILD_PROGRESS
}
