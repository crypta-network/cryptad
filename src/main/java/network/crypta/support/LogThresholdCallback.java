package network.crypta.support;

/**
 * Callback notified when logging thresholds change.
 *
 * <p>Implementations are invoked after the global or detailed logging thresholds are updated.
 * Typical implementations cache the result of {@link Logger#shouldLog} for specific classes or tags
 * to avoid repeated threshold checks on hot paths.
 *
 * <p>This is a functional interface to make registration concise in both Java and Kotlin.
 */
@FunctionalInterface
public interface LogThresholdCallback {
  /** Called when log thresholds may have changed and cached flags should be refreshed. */
  void shouldUpdate();
}
