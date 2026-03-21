package network.crypta.clients.fcp;

import java.util.Objects;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Builds the core-backed dependency bundle used by FCP server bootstrap.
 *
 * <p>This factory is intentionally local to {@code clients.fcp}. Callers use it at the bootstrap
 * boundary, typically from node startup code such as {@code NodeClientPersistence}, to translate
 * the remaining {@link NodeClientCore}-backed services into the narrow package-local seams that
 * {@link FCPServer} accepts. That keeps the server constructor and configuration registrar free of
 * direct daemon-core references while preserving the runtime behavior that older code paths
 * expected.
 *
 * <p>The factory is stateless and creates one fresh {@link FcpServerDependencies} bundle per call.
 * Each bundle contains lightweight adapters over live daemon services rather than detached
 * snapshots, so later requests still observe the current transfer-access policy, client context,
 * and persistence state exposed by the node.
 *
 * <ul>
 *   <li>Builds server-owned runtime support for listener, persistence, and connection plumbing.
 *   <li>Builds message-path runtime support for residual FCP protocol handlers.
 *   <li>Preserves the intentional split between server-owned and core-owned transfer policy
 *       lookups.
 * </ul>
 *
 * @see FCPServer
 * @see FcpServerDependencies
 */
public final class CoreFcpServerDependenciesFactory {
  private CoreFcpServerDependenciesFactory() {}

  /**
   * Builds the full dependency bundle required by {@link FCPServer}.
   *
   * <p>This method preserves the transfer-policy split introduced by the FCP decoupling work.
   * Normal server-owned fetch support reads transfer access from the supplied {@code runtimePorts},
   * because those flows are owned by the surrounding server runtime. Message fetch and insert
   * support continue to consult {@code core.getRuntimePorts().transferAccess()}, matching the
   * legacy behavior for inbound message handling and upload validation. The returned bundle is
   * ready to pass directly into {@link FCPServer#maybeCreate(FcpServerDependencies,
   * network.crypta.config.Config)} or the package-local server constructor.
   *
   * @param core live daemon core that backs the remaining core-owned FCP runtime seams
   * @param runtimePorts runtime SPI bridge used by server-owned FCP infrastructure and fetch flows
   * @param persistentRoot persistence root used to resolve global clients and durable request state
   * @return fully built dependency bundle that wires {@link FCPServer} without storing the core
   * @throws NullPointerException if {@code core}, {@code runtimePorts}, or {@code persistentRoot}
   *     is {@code null}
   */
  public static FcpServerDependencies create(
      NodeClientCore core, RuntimePorts runtimePorts, PersistentRequestRoot persistentRoot) {
    NodeClientCore nonNullCore = Objects.requireNonNull(core);
    RuntimePorts nonNullRuntimePorts = Objects.requireNonNull(runtimePorts);
    PersistentRequestRoot nonNullPersistentRoot = Objects.requireNonNull(persistentRoot);

    FcpServerRuntimeSupport serverRuntimeSupport = new CoreFcpServerRuntimeSupport(nonNullCore);
    FcpMessageRuntimeSupport messageRuntimeSupport = new CoreFcpMessageRuntimeSupport(nonNullCore);
    FcpFetchRuntimeSupport fetchRuntimeSupport =
        new CoreFcpFetchRuntimeSupport(nonNullCore, nonNullRuntimePorts::transferAccess);
    FcpFetchRuntimeSupport messageFetchRuntimeSupport =
        new CoreFcpFetchRuntimeSupport(
            nonNullCore, () -> nonNullCore.getRuntimePorts().transferAccess());
    FcpInsertRuntimeSupport insertRuntimeSupport =
        new CoreFcpInsertRuntimeSupport(
            nonNullCore, () -> nonNullCore.getRuntimePorts().transferAccess());
    return new FcpServerDependencies(
        nonNullRuntimePorts,
        nonNullPersistentRoot,
        serverRuntimeSupport,
        messageRuntimeSupport,
        fetchRuntimeSupport,
        messageFetchRuntimeSupport,
        insertRuntimeSupport);
  }
}
