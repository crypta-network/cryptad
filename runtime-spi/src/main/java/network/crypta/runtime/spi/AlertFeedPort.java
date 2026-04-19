package network.crypta.runtime.spi;

/**
 * Read-only detached alert surface exposed to admin-facing runtime consumers.
 *
 * <p>This port gives higher layers a stable way to inspect the current alert state without taking a
 * dependency on runtime alert implementations. Callers typically use it to populate management UIs,
 * JSON endpoints, or other local operator tooling that needs an ordered list of visible alerts and
 * their detached metadata. The port is intentionally narrow: it exposes snapshots only and leaves
 * alert lifecycle, registration, and rendering policy to the runtime and transport layers.
 */
public interface AlertFeedPort {
  /**
   * Returns a detached snapshot of the current visible alerts.
   *
   * <p>Implementations should preserve the runtime-defined encounter order so callers can render
   * alerts consistently across surfaces. The returned snapshot should be detached from any live
   * runtime alert objects and safe to retain for the lifetime of one request or render pass.
   *
   * @return immutable list snapshot of the current visible alerts in runtime-defined order
   */
  AlertListSnapshot snapshot();
}
