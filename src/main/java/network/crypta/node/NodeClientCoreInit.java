package network.crypta.node;

import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.Config;
import network.crypta.config.SubConfig;

/**
 * Bundles configuration inputs required to initialize {@link NodeClientCore}.
 *
 * <p>This record is a small, immutable carrier for the configuration objects and server wiring
 * needed during client-core startup. It keeps related inputs together so call sites can pass a
 * single value through initialization flows without threading multiple parameters across several
 * methods. Typical usage is to construct it once, then pass it to initialization helpers that read
 * the accessors to configure persistence, networking, and client-facing endpoints.
 *
 * <p>The record itself is shallowly immutable: its component references never change after
 * construction, but the referenced objects may still be mutable and managed elsewhere. Callers may
 * supply {@code null} components when a particular subsystem is intentionally absent; consumers
 * must handle such cases explicitly.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Holding the root {@link Config} and relevant {@link SubConfig} sections.
 *   <li>Providing access to the {@link SimpleToadletServer} used by HTTP toadlets.
 *   <li>Keeping startup wiring cohesive and easy to pass across layers.
 * </ul>
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * NodeClientCoreInit init =
 *     new NodeClientCoreInit(config, nodeConfig, installConfig, toadlets);
 * Config root = init.config();
 * }</pre>
 *
 * @param config root configuration container used by client-core subsystems; may be {@code null}
 * @param nodeConfig node-specific sub-configuration used during initialization; may be {@code null}
 * @param installConfig installation sub-configuration for path and store setup; may be {@code null}
 * @param toadlets HTTP toadlet server instance used for client endpoints; may be {@code null}
 * @see NodeClientCore
 * @see NodeClientPersistence
 * @see ClientEndpoints
 */
public record NodeClientCoreInit(
    Config config, SubConfig nodeConfig, SubConfig installConfig, SimpleToadletServer toadlets) {}
