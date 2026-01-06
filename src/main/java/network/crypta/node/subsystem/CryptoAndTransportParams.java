package network.crypta.node.subsystem;

import network.crypta.config.SubConfig;
import network.crypta.node.SecurityLevels;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;

/**
 * Parameter bundle that captures the inputs required to initialize crypto and transport services.
 *
 * <p>This record groups the configuration, executor, shutdown hook, security levels, and startup
 * flags used by {@link NodeNetworkSubsystem#initCryptoAndTransport(CryptoAndTransportParams, int)}
 * into a single immutable carrier. The grouping keeps call sites readable and avoids large
 * parameter lists while preserving the original initialization semantics. Callers construct a
 * single instance during node startup and pass it to the subsystem; the record does not validate
 * values and stores each reference as provided.
 *
 * <p>The record is immutable and thread-safe. It is intended for one-time initialization during
 * startup rather than for reuse across nodes or repeated reconfiguration. Each field should be
 * non-null unless explicitly documented as optional, and callers should ensure referenced objects
 * remain valid for the duration of the initialization sequence.
 *
 * <ul>
 *   <li><b>Responsibilities:</b> hold initialization inputs for crypto and transport setup.
 *   <li><b>Notable behaviors:</b> no validation or side effects; values are stored verbatim.
 * </ul>
 *
 * @param nodeConfig node configuration section used to register crypto options; must be non-null
 * @param oldConfig previous persisted field set for legacy sanity checks; may be {@code null}
 * @param executor executor used by message core and ticker initialization; must be non-null
 * @param shutdownHook shutdown hook used to register early stop tasks; must be non-null
 * @param securityLevels security level manager used for crypto configuration; must be non-null
 * @param startupTime node startup timestamp in milliseconds since epoch
 * @param enableARKs whether to enable ARK fetching during crypto initialization
 * @see NodeNetworkSubsystem#initCryptoAndTransport(CryptoAndTransportParams, int)
 */
public record CryptoAndTransportParams(
    SubConfig nodeConfig,
    SimpleFieldSet oldConfig,
    PriorityAwareExecutor executor,
    SemiOrderedShutdownHook shutdownHook,
    SecurityLevels securityLevels,
    long startupTime,
    boolean enableARKs) {}
