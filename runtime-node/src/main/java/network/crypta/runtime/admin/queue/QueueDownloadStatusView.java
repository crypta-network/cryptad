package network.crypta.runtime.admin.queue;

/**
 * Describes the runtime-owned view of a queued download request.
 *
 * <p>This subtype lets runtime-admin distinguish downloads from other queue entries without
 * importing backend-specific request classes. The extra download-specific flag is small but
 * important: legacy cleanup behavior treats downloads targeting temporary space differently from
 * normal persistent downloads.
 */
public interface QueueDownloadStatusView extends QueueRequestStatusView {
  /**
   * Returns whether the download currently targets temporary space.
   *
   * <p>Temporary-space downloads are intentionally excluded from the finished-download cleanup path
   * even when they otherwise look successful and finalized. Callers therefore use this flag only as
   * a policy input for queue administration, not as a general storage description.
   *
   * @return {@code true} when the download currently writes into temporary space
   */
  boolean toTempSpace();
}
