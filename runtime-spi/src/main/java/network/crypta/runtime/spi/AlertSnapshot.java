package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Detached snapshot of one alert entry exposed through the runtime SPI.
 *
 * <p>This record is the stable value object that crosses from runtime-owned alert machinery into
 * detached consumers such as Platform API and the Web Shell. It carries only JDK types, making it
 * safe to serialize, cache for the lifetime of one request, and compare in tests without keeping
 * references to live runtime alert implementations. The record is intentionally descriptive rather
 * than behavioral: it does not expose dismissal callbacks, HTML fragments, or feed helpers.
 *
 * <p>The identifier and textual fields preserve the current alert manager contract. In particular,
 * {@link #id()} is the detached identifier used for dismiss actions, {@link #text()} may contain
 * multi-line plain text, and {@link #dismissLabel()} may be {@code null} when the runtime has no
 * specialized label to expose. Consumers should treat {@link #updatedTimeMillis()} as an ordering
 * and freshness hint, not a guarantee about wall-clock precision.
 *
 * @param id stable alert identifier used for dismiss actions
 * @param title alert title shown in compact and expanded views
 * @param shortText short summary shown in constrained placements
 * @param text full plain-text body of the alert
 * @param severity detached alert severity mapped from the legacy priority class
 * @param dismissible whether the alert may be dismissed by the user
 * @param dismissLabel localized label for the dismiss action when the alert is dismissible; may be
 *     {@code null} when the runtime does not supply one
 * @param eventNotification whether the alert is a transient event notification
 * @param updatedTimeMillis last update time in milliseconds since the Unix epoch
 */
public record AlertSnapshot(
    int id,
    String title,
    String shortText,
    String text,
    AlertSeverity severity,
    boolean dismissible,
    String dismissLabel,
    boolean eventNotification,
    long updatedTimeMillis) {

  /**
   * Creates one detached alert snapshot.
   *
   * <p>The compact constructor enforces the one non-optional enum field required by the detached
   * contract. Other textual fields may be empty or {@code null} when the runtime does not provide a
   * value.
   */
  public AlertSnapshot {
    Objects.requireNonNull(severity, "severity");
  }
}
