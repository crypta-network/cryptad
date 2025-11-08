package network.crypta.client;

import java.io.Serial;

/**
 * Signals that an archive-related operation should be restarted rather than treated as a terminal
 * failure.
 *
 * <p>This checked exception communicates that progress is not possible in the current attempt but
 * may succeed after a retry. Typical reasons include the archive manifest changing between reads,
 * caches being invalidated, or dependent inputs becoming available only after an earlier step
 * completes. Callers generally catch this exception, perform any lightweight cleanup, and then
 * reschedule the operation using their normal retry or backoff policy. Unlike {@link
 * ArchiveFailureException}, which denotes an unrecoverable condition, this type indicates a
 * transient state that is expected to clear.
 *
 * <p>The exception is immutable and thread-safe. Messages are intended for diagnostic logs and are
 * not localized. The type itself carries no retry timing; that policy is defined by the caller or
 * scheduler.
 *
 * <ul>
 *   <li>Checked exception: callers must catch or declare it.
 *   <li>Retryable semantics: use normal retry/backoff mechanisms.
 *   <li>Immutable: safe to pass across threads after creation.
 * </ul>
 */
public class ArchiveRestartException extends Exception {

  @Serial private static final long serialVersionUID = -7670838856130773012L;

  /**
   * Create a new restart signal with a descriptive message.
   *
   * <p>Use this when an archive operation should be attempted again because prerequisites may have
   * changed or additional data may become available. The message should summarize the immediate
   * reason for requesting a restart so that logs and metrics remain actionable.
   *
   * @param msg human-readable description that explains why a restart is appropriate; include any
   *     useful context such as entry names, versions, or detection conditions. Not localized and
   *     typically intended for diagnostic logs rather than direct UI display.
   */
  public ArchiveRestartException(String msg) {
    super(msg);
  }
}
