package network.crypta.support.api;

import network.crypta.config.ConfigCallback;

/**
 * Callback for configuration options that use {@link Integer} values.
 *
 * <p>Implementations expose the current value via {@link ConfigCallback#get()} and apply updates in
 * {@link ConfigCallback#set(Object)}. Validation and units (e.g., bytes, seconds) are
 * option-specific and should be enforced in {@code set}.
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
public abstract class IntCallback extends ConfigCallback<Integer> {}
