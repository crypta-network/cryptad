package network.crypta.runtime.fcp;

import network.crypta.client.async.persistence.PersistentRequestCatalog;
import network.crypta.client.async.persistence.PersistentRequestCoordinator;
import network.crypta.client.async.persistence.PersistentRequestHandle;
import network.crypta.client.async.persistence.PersistentRequestRecoveryCodec;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.endpoints.fcp.FcpEndpointHandle;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Runtime-owned seam for the FCP persistent-request bundle used during client-core startup.
 *
 * <p>This interface captures the exact persistent-request services that higher-level runtime code
 * needs while bootstrapping the client layer and later exposing the FCP endpoint. The seam keeps
 * the concrete FCP request root, catalog adapter, recovery codec, and endpoint bootstrap logic on
 * the bridge side of the boundary, while {@code NodeClientPersistence} and other runtime-owned code
 * depend only on this narrow bundle.
 *
 * <p>Each implementation is expected to represent one shared persistent-request state bundle. The
 * coordinator, catalog, snapshot view, and endpoint handle creation should all remain aligned to
 * the same underlying durable request root, so startup ordering and recovery behavior stay
 * unchanged. Callers normally create one bundle during {@code NodeClientPersistence} construction,
 * reuse it when wiring the client-layer persistence adapters, and then ask the same bundle to
 * create the FCP endpoint handle later in startup. That usage pattern keeps the runtime seam narrow
 * while preserving the historical relationship between request recovery, request cataloging, and
 * FCP server bootstrap.
 */
public interface PersistentRequestEndpointServices {

  /**
   * Returns the coordinator used by client-context persistence flows.
   *
   * <p>The returned coordinator is the runtime entry point for registering, resuming, and
   * deregistering durable requests as the client layer rebuilds its state. Implementations should
   * return the coordinator backed by the same durable request root exposed through the rest of this
   * bundle, rather than a detached adapter.
   *
   * @return persistent-request coordinator for durable request ownership, recovery, and lifecycle
   *     callbacks
   */
  PersistentRequestCoordinator coordinator();

  /**
   * Returns the catalog used to list and deduplicate persistent requests.
   *
   * <p>The catalog is the read-mostly view used by persistence and endpoint layers when they need a
   * stable lookup surface for already-known requests. It should observe the same underlying durable
   * request state as {@link #coordinator()} and {@link #getPersistentRequests()} so request
   * discovery and deduplication remain consistent during startup and recovery.
   *
   * @return catalog view over the persistent-request state managed by this bundle
   */
  PersistentRequestCatalog catalog();

  /**
   * Returns the recovery codec used to reconstruct persistent requests from the saved state.
   *
   * <p>The recovery codec translates persisted client-layer records back into live request objects.
   * Implementations should return the codec paired with the same coordinator and request root used
   * elsewhere in this bundle so deserialized requests register against the correct persistent
   * state.
   *
   * @return recovery codec for durable request restart within this bundle's request state
   */
  PersistentRequestRecoveryCodec recoveryCodec();

  /**
   * Returns a snapshot of the currently registered persistent requests.
   *
   * <p>The returned array is a point-in-time snapshot. Later registrations, completions, or
   * removals do not need to be reflected in the previously returned array instance. Callers can use
   * this snapshot to seed runtime-owned endpoint handles without depending on bridge-owned request
   * root types directly.
   *
   * @return snapshot array of persistent request handles; never {@code null} but possibly empty
   */
  PersistentRequestHandle[] getPersistentRequests();

  /**
   * Creates the runtime-owned FCP endpoint handle backed by this persistent-request bundle.
   *
   * <p>Implementations should use the durable request state represented by this bundle when
   * building the endpoint handle, so the eventual FCP server sees the same coordinator, catalog
   * contents, and recovered requests that the client layer already uses. The method selects the
   * concrete endpoint-side bootstrap path, but the returned handle remains the runtime-owned
   * wrapper exposed upstream.
   *
   * @param node live daemon node supplying configuration, services, and persisted startup state
   * @param core client core whose schedulers and persistence services back the FCP endpoint
   * @param runtimePorts runtime SPI bridge passed to the FCP infrastructure during endpoint
   *     creation
   * @return runtime-owned handle for the configured FCP endpoint backed by this bundle's request
   *     state
   */
  FcpEndpointHandle createFcpEndpointHandle(
      Node node, NodeClientCore core, RuntimePorts runtimePorts);
}
