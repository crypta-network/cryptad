package network.crypta.config;

/**
 * Specialized configuration callback for string-valued options.
 *
 * <p>This type narrows {@link ConfigCallback} to {@link String} and is the canonical textual
 * callback type for new APIs in {@code :foundation-config}. It is used by the configuration
 * subsystem to read and update options whose value is textual, including ordinary {@link
 * StringOption} values and configuration-facing adapters such as filesystem path callbacks.
 * Implementations provide the mechanism to retrieve the current value and to apply a new one,
 * including any validation and persistence required by the owning option or subsystem.
 *
 * <p>The class extends the deprecated bridge in {@link network.crypta.support.api.StringCallback}.
 * That keeps runtime callback objects assignable through both package names while the canonical API
 * surface moves into the module that actually owns configuration behavior.
 *
 * <p>Thread-safety and handling of {@code null} are defined by the concrete implementation; callers
 * must follow the specific option's contract. The inherited {@link ConfigCallback#get()} returns
 * the current effective value. The inherited {@link ConfigCallback#set(Object)} applies a new value
 * and may reject it as invalid or indicate that a node restart is required, depending on
 * implementation.
 *
 * @see ConfigCallback
 * @see network.crypta.config.StringOption
 * @see network.crypta.config.InvalidConfigValueException
 * @see network.crypta.config.NodeNeedRestartException
 */
@SuppressWarnings("deprecation")
public abstract class StringCallback extends network.crypta.support.api.StringCallback {

  /**
   * Creates a string callback base instance.
   *
   * <p>This constructor performs no initialization. Concrete implementations commonly appear as
   * anonymous classes or narrow adapters owned by a subsystem. The constructor remains public to
   * preserve the access level of the implicit constructor that existed before the package move.
   */
  public StringCallback() {}
}
