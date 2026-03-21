package network.crypta.support.api;

import network.crypta.config.ConfigCallback;

/**
 * Callback for configuration options that use {@code String[]} values.
 *
 * <p>This specialization of {@link ConfigCallback} exposes the current effective value via {@link
 * ConfigCallback#get()} and applies updates in {@link ConfigCallback#set(Object)}.
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
public abstract class StringArrCallback extends ConfigCallback<String[]> {}
