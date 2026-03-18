package network.crypta.runtime.spi;

/**
 * User-facing rejection categories for queue insert creation.
 *
 * <p>These values represent the small set of rejection cases that the queue UI already knows how to
 * explain to the user. They keep caller-side response mapping stable while avoiding direct exposure
 * to daemon-specific exception types and policy classes.
 *
 * <p>The enum is intentionally narrow. Outcomes such as identifier collisions and unresolved
 * metadata stay on the normal {@link QueueInsertOutcome} path, while broader queue availability
 * problems use {@link RequestQueueUnavailableException}.
 */
public enum QueueInsertFailureReason {
  /**
   * Runtime policy rejected the selected upload, file, or directory source.
   *
   * <p>Typical causes include access-control checks or local-security policies that refuse the
   * source before a persistent insert is started.
   */
  ACCESS_DENIED,

  /**
   * The requested file or directory is missing or unreadable.
   *
   * <p>Callers usually map this reason to the existing "no file selected" or "cannot read" response
   * path rather than treating it as an internal daemon failure.
   */
  SOURCE_NOT_FOUND,

  /**
   * The selected directory exceeds the legacy inserter's per-request file limit.
   *
   * <p>This reason is specific to the directory inserts and preserves the queue page's existing
   * too-many-files error page.
   */
  TOO_MANY_FILES
}
