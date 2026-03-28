package network.crypta.runtime.alerts;

import java.util.Objects;
import network.crypta.client.async.alerts.ClientAlert;
import network.crypta.client.async.alerts.ClientAlertSink;

/**
 * Adapts the client-owned alert seam to the runtime {@link UserAlertManager}.
 *
 * <p>This adapter is the runtime-side bridge for the new client alert seam. Client code posts the
 * neutral {@link ClientAlert} marker through {@link ClientAlertSink}; this class performs the
 * runtime-specific check that the value is actually a {@link UserAlert} and then forwards it to the
 * existing {@link UserAlertManager}. Keeping that knowledge here preserves the existing alert
 * manager behavior without leaking runtime-owned types back into the client layer.
 *
 * <p>The class is stateless apart from its manager reference and is safe to reuse wherever the same
 * {@link UserAlertManager} instance should receive client-originated alerts. Unsupported alert
 * implementations are rejected immediately, so type mismatches fail at the boundary instead of
 * being silently ignored.
 */
public final class UserAlertManagerClientAlertSink implements ClientAlertSink {
  private final UserAlertManager userAlertManager;

  /**
   * Creates an adapter that forwards runtime user alerts to the given manager.
   *
   * <p>Callers usually construct this once during node startup and pass it into {@code
   * ClientContext.init(...)}. The adapter keeps a direct reference to the manager and does not add
   * buffering, synchronization, or translation beyond the alert type check performed in {@link
   * #post(ClientAlert)}.
   *
   * @param userAlertManager runtime alert manager that should receive forwarded client alerts and
   *     must not be {@code null}
   * @throws NullPointerException if the supplied runtime alert manager is {@code null}
   */
  public UserAlertManagerClientAlertSink(UserAlertManager userAlertManager) {
    this.userAlertManager = Objects.requireNonNull(userAlertManager, "userAlertManager");
  }

  /**
   * Posts a client-layer alert to the runtime manager when it is a runtime {@link UserAlert}.
   *
   * <p>This method enforces the boundary contract for the runtime side of the seam. A {@link
   * UserAlert} is forwarded unchanged to {@link UserAlertManager#register(UserAlert)} so the
   * existing runtime alert lifecycle remains intact. Any other {@link ClientAlert}, including
   * {@code null}, is rejected immediately because this adapter only knows how to register runtime
   * user alerts.
   *
   * @param alert client-layer alert to validate and forward to the runtime alert manager
   * @throws IllegalArgumentException if {@code alert} is {@code null} or not a {@link UserAlert}
   */
  @Override
  public void post(ClientAlert alert) {
    if (!(alert instanceof UserAlert userAlert)) {
      throw new IllegalArgumentException("alert must be a UserAlert");
    }
    userAlertManager.register(userAlert);
  }
}
