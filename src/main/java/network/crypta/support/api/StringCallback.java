package network.crypta.support.api;

import network.crypta.config.ConfigCallback;

/**
 * Specialized configuration callback for string-valued options.
 *
 * <p>This type narrows {@link ConfigCallback} to {@link String} and is used by the configuration
 * subsystem to read and update options whose value is textual. Implementations provide the
 * mechanism to retrieve the current value and to apply a new one, including any validation and
 * persistence required by the owning option or subsystem.
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
public abstract class StringCallback extends ConfigCallback<String> {}
