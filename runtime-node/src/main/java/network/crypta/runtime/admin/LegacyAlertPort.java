package network.crypta.runtime.admin;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.spi.AlertFeedPort;
import network.crypta.runtime.spi.AlertListSnapshot;
import network.crypta.runtime.spi.AlertMutationPort;
import network.crypta.runtime.spi.AlertSeverity;
import network.crypta.runtime.spi.AlertSnapshot;

/**
 * Bridges the runtime alert manager to the detached alert SPI.
 *
 * <p>This adapter is the runtime-node side of the new alert boundary. It keeps the live {@link
 * UserAlertManager} and its rich alert types inside the daemon module, then projects the current
 * alert state into the small JDK-only DTOs defined in {@code :runtime-spi}. That lets admin-facing
 * callers such as Platform API handlers and legacy HTTP bridges work with stable, serializable
 * alert data without importing runtime-owned alert implementations, HTML fragments, or feed
 * helpers.
 *
 * <p>The adapter intentionally stays mechanical. It preserves manager ordering, forwards dismissals
 * unchanged, and filters out alerts that are already invalid at snapshot time. It does not cache
 * results, merge alerts, or interpret alert semantics beyond the field mapping needed for the
 * detached SPI.
 */
final class LegacyAlertPort implements AlertFeedPort, AlertMutationPort {
  /** Live alert manager that remains the owner of alert ordering and dismissal semantics. */
  private final UserAlertManager alertManager;

  /**
   * Creates a detached alert adapter backed by the live alert manager.
   *
   * <p>Callers normally create one adapter and reuse it for both alert reads and dismissals so both
   * operations see the same underlying manager. The adapter does not assume exclusive ownership of
   * the manager; other runtime code may continue to register, invalidate, or dismiss alerts in
   * parallel.
   *
   * @param alertManager shared runtime alert manager
   * @throws NullPointerException if {@code alertManager} is {@code null}
   */
  LegacyAlertPort(UserAlertManager alertManager) {
    this.alertManager = Objects.requireNonNull(alertManager, "alertManager");
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned snapshot preserves the manager's encounter order and excludes alerts that are
   * already invalid at the moment they are inspected. That mirrors the legacy operator-facing
   * surfaces, which only show alerts that remain active, while still leaving the underlying alert
   * lifecycle entirely under manager control.
   */
  @Override
  public AlertListSnapshot snapshot() {
    UserAlert[] alerts = alertManager.getAlerts();
    List<AlertSnapshot> snapshots = new ArrayList<>(alerts.length);
    for (UserAlert alert : alerts) {
      if (!alert.isValid()) {
        continue;
      }
      snapshots.add(toSnapshot(alert));
    }
    return new AlertListSnapshot(snapshots);
  }

  /**
   * {@inheritDoc}
   *
   * <p>Dismissal is delegated directly to the live manager so the runtime retains its existing side
   * effects, including unregister-on-dismiss behavior and per-alert cleanup hooks. The detached
   * adapter does not add not-found handling or authorization checks.
   */
  @Override
  public void dismiss(int alertId) {
    alertManager.dismissAlert(alertId);
  }

  /**
   * Converts one runtime-owned alert into the detached SPI snapshot used by higher layers.
   *
   * <p>The mapping copies only the values required by the current detached contract: identifier,
   * textual content, severity, dismissal metadata, event-notification state, and update time. No
   * runtime-owned alert object escapes the method.
   *
   * @param alert live alert instance from the runtime manager snapshot
   * @return detached alert snapshot carrying only JDK values
   */
  private static AlertSnapshot toSnapshot(UserAlert alert) {
    return new AlertSnapshot(
        alert.hashCode(),
        alert.getTitle(),
        alert.getShortText(),
        alert.getText(),
        AlertSeverity.fromPriorityClass(alert.getPriorityClass()),
        alert.userCanDismiss(),
        alert.dismissButtonText(),
        alert.isEventNotification(),
        alert.getUpdatedTime());
  }
}
