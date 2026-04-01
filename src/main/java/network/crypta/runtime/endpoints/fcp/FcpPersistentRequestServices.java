package network.crypta.runtime.endpoints.fcp;

import java.util.Objects;
import network.crypta.client.async.persistence.PersistentRequestCatalog;
import network.crypta.client.async.persistence.PersistentRequestCoordinator;
import network.crypta.client.async.persistence.PersistentRequestHandle;
import network.crypta.client.async.persistence.PersistentRequestRecoveryCodec;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.fcp.PersistentRequestEndpointServices;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Bridge-owned holder for concrete FCP persistent-request infrastructure.
 *
 * <p>This service keeps the legacy {@link PersistentRequestRoot}, request-catalog adapter, recovery
 * codec, and FCP endpoint creation logic inside {@code runtime.endpoints.fcp}. Callers in the
 * top-level runtime package interact only with the narrower runtime-owned {@link
 * PersistentRequestEndpointServices} seam, the client-owned persistence seams it exposes, and the
 * runtime-owned {@link FcpEndpointHandle}.
 *
 * <p>Each instance owns one shared persistent-request root and the adapters derived from it. That
 * keeps request enumeration, recovery, owner lookup, and endpoint creation aligned around the same
 * durable state without forcing top-level runtime packages to import legacy FCP types. Typical
 * usage is to construct this service once during runtime bootstrap, pass its seam views into
 * client-layer persistence wiring, and later ask it to create the endpoint handle that will expose
 * the same persistent state to the running node.
 */
public final class FcpPersistentRequestServices implements PersistentRequestEndpointServices {
  private final PersistentRequestRoot persistentRoot;
  private final PersistentRequestCatalog catalog;
  private final PersistentRequestRecoveryCodec recoveryCodec;

  /** Creates bridge-owned persistent-request services backed by a fresh FCP request root. */
  public FcpPersistentRequestServices() {
    persistentRoot = new PersistentRequestRoot();
    catalog = new CoreFcpPersistentRequestCatalog(persistentRoot);
    recoveryCodec = new FcpPersistentRequestRecoveryCodec();
  }

  /**
   * Returns the coordinator used by client-context persistence flows.
   *
   * <p>The returned coordinator resolves or recreates the runtime-owned persistent client for a
   * durable request during creation and recovery. It is backed by the same shared request root used
   * by this service's catalog and endpoint creation logic, so client-layer persistence work stays
   * consistent with the live FCP queue state.
   *
   * @return persistent-request coordinator backed by the bridge-owned request root
   */
  @Override
  public PersistentRequestCoordinator coordinator() {
    return persistentRoot;
  }

  /**
   * Returns the client-owned catalog seam for listing and deduplicating persistent requests.
   *
   * <p>Callers use this catalog during checkpoint and startup replay to list the durable requests
   * that currently exist and to avoid restoring duplicates. The adapter preserves the legacy FCP
   * request-identity rules while still exposing only the client-owned catalog interface.
   *
   * @return persistent-request catalog backed by the bridge-owned request root
   */
  @Override
  public PersistentRequestCatalog catalog() {
    return catalog;
  }

  /**
   * Returns the client-owned recovery codec seam for reconstructing persistent requests.
   *
   * <p>This codec reconstructs persistent FCP requests from compact recovery data while leaving the
   * outer persistence framing to the client layer. Keeping the codec here lets the runtime package
   * evolve its FCP-specific restart logic without widening the persistence SPI.
   *
   * @return recovery codec that restores FCP persistent requests through the seam
   */
  @Override
  public PersistentRequestRecoveryCodec recoveryCodec() {
    return recoveryCodec;
  }

  /**
   * Returns a snapshot of the currently registered persistent requests.
   *
   * <p>The returned array is a point-in-time snapshot from the shared request root. Later queue
   * changes are not reflected in the same array instance. Callers should treat the contents as
   * durable request handles rather than depending on the concrete FCP request implementations that
   * happen to back them today.
   *
   * @return snapshot of persistent request handles; never {@code null}
   */
  @Override
  public PersistentRequestHandle[] getPersistentRequests() {
    return persistentRoot.getPersistentRequests();
  }

  /**
   * Creates the runtime-owned FCP endpoint handle for this node and core.
   *
   * <p>The concrete {@link FCPServer} remains owned by this bridge package. Callers receive only
   * the narrower runtime-owned handle and can continue to treat it as the client-layer download
   * cache. The created endpoint shares this service's persistent-request root, which preserves the
   * existing relationship between queue ownership, request recovery, and FCP startup without
   * leaking concrete bridge types back into the top-level runtime package.
   *
   * @param node node instance supplying configuration and shared services
   * @param core client core used by the FCP server
   * @param runtimePorts runtime SPI bridge passed to FCP infrastructure
   * @return runtime-owned handle that wraps the configured FCP server
   * @throws NullPointerException if any required dependency is {@code null}
   */
  @Override
  public FcpEndpointHandle createFcpEndpointHandle(
      Node node, NodeClientCore core, RuntimePorts runtimePorts) {
    Node nonNullNode = Objects.requireNonNull(node, "node");
    FCPServer server =
        FCPServer.maybeCreate(
            CoreFcpServerDependenciesFactory.create(
                Objects.requireNonNull(core, "core"),
                Objects.requireNonNull(runtimePorts, "runtimePorts"),
                persistentRoot),
            nonNullNode.getConfig());
    return FcpEndpointHandles.wrap(server);
  }
}
