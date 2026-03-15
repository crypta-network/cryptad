package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Signals that the runtime rejected an add-peer request while preserving legacy failure semantics.
 *
 * <p>This checked exception separates protocol-facing add-peer handling from daemon-only error
 * classes. The runtime adapter chooses one {@link PeerAddFailureReason} and preserves a
 * human-readable detail message so the caller can continue mapping failures onto the same
 * protocol-level responses used before the SPI migration.
 */
public final class PeerAddRejectedException extends Exception {
  private final PeerAddFailureReason reason;

  /**
   * Creates an add-peer rejection with a preserved legacy reason code.
   *
   * <p>The detail message is intentionally stored as the exception message because some higher
   * layers surface that text directly after translating the reason into their own wire-level error
   * family.
   *
   * @param reason categorized legacy failure reason; must not be {@code null}
   * @param detailMessage human-readable detail that higher layers may surface unchanged
   */
  public PeerAddRejectedException(PeerAddFailureReason reason, String detailMessage) {
    super(detailMessage);
    this.reason = Objects.requireNonNull(reason, "reason");
  }

  /**
   * Returns the categorized legacy failure reason.
   *
   * <p>This value is stable enough for protocol mapping and avoids exposing transport-specific or
   * daemon-specific exception types to callers.
   *
   * @return add-peer failure reason
   */
  public PeerAddFailureReason reason() {
    return reason;
  }
}
