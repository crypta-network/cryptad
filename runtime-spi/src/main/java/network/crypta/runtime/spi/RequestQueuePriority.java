package network.crypta.runtime.spi;

/**
 * Queue priorities understood by the runtime request-queue SPI.
 *
 * <p>This enum captures only the scheduling distinctions that the current persistent-request
 * control paths need. The values are intentionally coarse so the SPI can stay stable even if the
 * daemon continues to use finer-grained native priorities internally. Callers should select the
 * smallest value that preserves historical behavior rather than treating this as a user-facing or
 * policy-rich priority system.
 */
public enum RequestQueuePriority {
  /**
   * Default priority for routine persistent-request lookups or updates.
   *
   * <p>Use this for ordinary control operations where low latency is helpful but not urgent enough
   * to jump ahead of the rest of the persistent-request workload.
   */
  NORMAL,

  /**
   * Elevated priority for urgent removals or similar user-visible control operations.
   *
   * <p>This priority preserves the legacy behavior for queue-control actions that should complete
   * promptly because they directly unblock or stop ongoing persistent work.
   */
  HIGH,

  /**
   * Priority used for persistent listing work, matching the legacy listing queue semantics.
   *
   * <p>Listing is intentionally separated from {@link #NORMAL} so callers can preserve the
   * historical ordering used when listing persistent requests without promoting the work all the
   * way to {@link #HIGH}.
   */
  LISTING
}
