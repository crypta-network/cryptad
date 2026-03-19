package network.crypta.runtime.spi;

/**
 * Queue-completion tracking capability exposed through the runtime SPI.
 *
 * <p>This port gives higher layers one minimal hook to ensure the daemon-side completion-tracking
 * machinery is active for the selected queue side. The HTTP layer does not need to know how
 * completion callbacks are registered, how completed identifiers are persisted and replayed, or how
 * completion alerts are emitted; it only requests that the runtime start that tracking when needed.
 *
 * <p>The operation must be idempotent per queue side. Calling {@link
 * #ensureTrackingStarted(boolean)} repeatedly for downloads or uploads must not register duplicate
 * callbacks or repeat one-time recovery work for that side.
 */
public interface QueueCompletionPort {
  /**
   * Ensures completion tracking has been started for the selected queue side.
   *
   * <p>The operation is idempotent per side. Repeated calls for the same side must not register
   * duplicate callbacks or duplicate recovery work.
   *
   * @param uploads {@code true} to start upload-side tracking, {@code false} for download-side
   *     tracking
   */
  void ensureTrackingStarted(boolean uploads);
}
