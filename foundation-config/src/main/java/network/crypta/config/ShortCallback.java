package network.crypta.config;

/**
 * Callback for configuration options that use {@link Short} values.
 *
 * <p>This specialization of {@link ConfigCallback} is intended for settings whose domain fits in a
 * 16-bit signed integer. New configuration APIs in {@code :foundation-config} should use this type
 * directly when registering {@link ShortOption} instances through {@link SubConfig}.
 * Implementations expose the current effective value via {@link ConfigCallback#get()} and apply
 * updates in {@link ConfigCallback#set(Object)}. Units, such as counts or milliseconds, and
 * validation rules remain option-specific and should be enforced by implementations.
 *
 * <p>The class extends the deprecated bridge in {@link network.crypta.support.api.ShortCallback} so
 * callback objects continue to satisfy code compiled against the old package. That preserves the
 * existing callback hierarchy while the canonical API moves under {@code network.crypta.config}.
 *
 * <p>Contract notes:
 *
 * <ul>
 *   <li><strong>Purpose:</strong> reflect and apply a short-valued configuration option.
 *   <li><strong>Inputs/outputs:</strong> {@link ConfigCallback#get()} returns the effective,
 *       non-{@code null} value; {@link ConfigCallback#set(Object)} receives the requested new
 *       value.
 *   <li><strong>Validation:</strong> implementations may reject invalid values by throwing {@link
 *       network.crypta.config.InvalidConfigValueException}; some changes may require a restart and
 *       signal this via {@link network.crypta.config.NodeNeedRestartException}.
 *   <li><strong>Threading:</strong> no synchronization guarantees are provided here; thread-safety
 *       depends on the concrete implementation and calling context.
 * </ul>
 *
 * @see network.crypta.config.ConfigCallback
 * @see network.crypta.config.ShortOption
 */
@SuppressWarnings("deprecation")
public abstract class ShortCallback extends network.crypta.support.api.ShortCallback {

  /**
   * Creates a short-valued callback base instance.
   *
   * <p>This constructor performs no initialization. It exists so this public abstract API surface
   * has explicit constructor documentation without changing the access level of the previously
   * implicit constructor.
   */
  public ShortCallback() {}
}
