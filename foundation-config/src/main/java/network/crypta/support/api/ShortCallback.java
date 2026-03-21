package network.crypta.support.api;

import network.crypta.config.ConfigCallback;

/**
 * Callback for configuration options that use {@link Short} values.
 *
 * <p>This specialization of {@link ConfigCallback} is intended for settings whose domain fits in a
 * 16-bit signed integer. Implementations expose the current effective value via {@link
 * ConfigCallback#get()} and apply updates in {@link ConfigCallback#set(Object)}. Units (e.g.,
 * counts, milliseconds) and validation rules are option-specific and should be enforced by
 * implementations.
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
public abstract class ShortCallback extends ConfigCallback<Short> {}
