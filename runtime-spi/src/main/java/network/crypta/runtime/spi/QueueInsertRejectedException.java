package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Signals that queue insert creation was rejected for a user-facing reason.
 *
 * <p>This checked exception represents rejection cases that callers are expected to map directly to
 * an existing queue error page. It deliberately separates policy-style failures such as
 * access-control denials from broader queue-unavailable conditions and from normal redirect-style
 * outcomes such as identifier collisions.
 *
 * <p>The exception carries a detached {@link QueueInsertFailureReason} so higher layers can keep
 * their existing response mapping without depending on daemon-owned exception classes.
 */
public class QueueInsertRejectedException extends Exception {
  /** Detached rejection category used for stable caller-side response mapping. */
  private final QueueInsertFailureReason reason;

  /**
   * Creates an exception with the supplied detached rejection reason and detail message.
   *
   * @param reason detached rejection category for caller-side response mapping
   * @param message human-readable explanation suitable for logs and debugging
   */
  public QueueInsertRejectedException(QueueInsertFailureReason reason, String message) {
    super(message);
    this.reason = Objects.requireNonNull(reason, "reason");
  }

  /**
   * Creates an exception with the supplied detached rejection reason, detail message, and cause.
   *
   * @param reason detached rejection category for caller-side response mapping
   * @param message human-readable explanation suitable for logs and debugging
   * @param cause underlying daemon-specific cause retained for diagnostics
   */
  public QueueInsertRejectedException(
      QueueInsertFailureReason reason, String message, Throwable cause) {
    super(message, cause);
    this.reason = Objects.requireNonNull(reason, "reason");
  }

  /**
   * Returns the detached rejection category associated with this failure.
   *
   * <p>The returned value is stable across runtime implementations and is intended for
   * caller-controlled response mapping rather than for end-user display text.
   *
   * @return rejection category used by higher layers for user-facing mapping
   */
  public QueueInsertFailureReason reason() {
    return reason;
  }
}
