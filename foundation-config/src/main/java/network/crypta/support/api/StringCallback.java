package network.crypta.support.api;

import network.crypta.config.ConfigCallback;

/**
 * Deprecated compatibility bridge for the callback package move to {@code network.crypta.config}.
 *
 * @deprecated Use {@link network.crypta.config.StringCallback}. Retained to preserve source and
 *     binary compatibility for existing {@code foundation-config} consumers.
 */
@Deprecated
public abstract class StringCallback extends ConfigCallback<String> {}
