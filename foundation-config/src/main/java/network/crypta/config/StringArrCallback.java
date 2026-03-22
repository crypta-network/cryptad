package network.crypta.config;

/**
 * Callback for configuration options that use {@code String[]} values.
 *
 * <p>This specialization of {@link ConfigCallback} is the canonical array-of-strings callback type
 * for new configuration APIs in {@code :foundation-config}. It commonly backs {@link
 * StringArrOption} registrations through {@link SubConfig}. Implementations expose the current
 * effective value via {@link ConfigCallback#get()} and apply updates in {@link
 * ConfigCallback#set(Object)}.
 *
 * <p>The class extends the deprecated bridge in {@link
 * network.crypta.support.api.StringArrCallback} so callback instances remain assignable to legacy
 * consumers while the canonical package moves under {@code network.crypta.config}. New code should
 * reference this type directly.
 *
 * <p>Contract and usage notes:
 *
 * <ul>
 *   <li><strong>Purpose:</strong> represent a sequence of strings as a single configuration option.
 *   <li><strong>Inputs/outputs:</strong> {@link ConfigCallback#get()} returns a non-{@code null}
 *       array (use an empty array to indicate “no entries”); {@link ConfigCallback#set(Object)}
 *       receives the requested new sequence.
 *   <li><strong>Validation:</strong> implementations may reject values by throwing {@link
 *       network.crypta.config.InvalidConfigValueException}; some changes may require a restart and
 *       signal this via {@link network.crypta.config.NodeNeedRestartException}.
 *   <li><strong>Threading:</strong> no synchronization guarantees are defined here; thread-safety
 *       depends on the concrete implementation and calling context.
 *   <li><strong>Mutability:</strong> callers should not modify the array returned from {@link
 *       ConfigCallback#get()} unless explicitly documented by the implementation. Prefer treating
 *       it as read-only and use {@link ConfigCallback#set(Object)} to apply changes.
 *   <li><strong>Semantics:</strong> whether order or duplicate elements are significant is
 *       option-specific.
 *   <li><strong>Persistence:</strong> when wired through {@link
 *       network.crypta.config.StringArrOption}, the configuration framework persists values as a
 *       semicolon-delimited list with URL-encoded elements; empty elements are encoded as {@code
 *       ":"}. See {@link network.crypta.config.StringArrOption} for exact rules.
 * </ul>
 *
 * @see network.crypta.config.ConfigCallback
 * @see network.crypta.config.StringArrOption
 */
@SuppressWarnings("deprecation")
public abstract class StringArrCallback extends network.crypta.support.api.StringArrCallback {

  /**
   * Creates a string-array callback base instance.
   *
   * <p>This constructor performs no initialization. Subclasses decide whether returned arrays are
   * defensive copies, immutable snapshots, or shared state views. The constructor remains public so
   * the documented API matches the access level of the formerly implicit constructor.
   */
  public StringArrCallback() {}
}
