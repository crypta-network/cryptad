package network.crypta.client.async;

import network.crypta.support.api.LockableRandomAccessBufferFactory;

/**
 * Holds random-access buffer factories used for transient and persistent client operations.
 *
 * @param tempRAFFactory factory for transient random-access buffers
 * @param persistentRAFFactory factory for persistent random-access buffers
 */
public record ClientContextRafFactories(
    LockableRandomAccessBufferFactory tempRAFFactory,
    LockableRandomAccessBufferFactory persistentRAFFactory) {}
