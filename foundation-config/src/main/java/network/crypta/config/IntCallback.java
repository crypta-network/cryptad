package network.crypta.config;

/**
 * Callback for configuration options that use {@link Integer} values.
 *
 * <p>This is the canonical integer callback type for new configuration APIs in {@code
 * :foundation-config}. It is typically paired with {@link IntOption} or {@link BandwidthOption} and
 * is registered through {@link SubConfig}. Implementations expose the current value via {@link
 * ConfigCallback#get()} and apply updates in {@link ConfigCallback#set(Object)}. Validation and
 * units, such as bytes, counts, or durations, remain option-specific and should be enforced in
 * {@code set}.
 *
 * <p>The class extends the deprecated compatibility bridge in {@link
 * network.crypta.support.api.IntCallback}. That keeps callback instances visible to consumers that
 * still reference the legacy package while establishing {@code network.crypta.config} as the
 * package owned by {@code :foundation-config}.
 *
 * <p>Contract notes:
 *
 * <ul>
 *   <li>{@link ConfigCallback#get()} returns the effective, non-null value currently in use.
 *   <li>{@link ConfigCallback#set(Object)} may reject invalid values by throwing {@link
 *       network.crypta.config.InvalidConfigValueException} and may request a restart by throwing
 *       {@link network.crypta.config.NodeNeedRestartException}, as defined by the {@link
 *       network.crypta.config.ConfigCallback} contract.
 * </ul>
 *
 * @see network.crypta.config.ConfigCallback
 */
@SuppressWarnings("deprecation")
public abstract class IntCallback extends network.crypta.support.api.IntCallback {

  /**
   * Creates an integer callback base instance.
   *
   * <p>This constructor performs no initialization. It exists so the public abstract type has an
   * explicitly documented constructor while preserving the same public access level as the implicit
   * constructor used before the package move.
   */
  public IntCallback() {}
}
