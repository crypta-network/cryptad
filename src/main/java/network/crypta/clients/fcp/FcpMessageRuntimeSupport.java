package network.crypta.clients.fcp;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.PeerNode;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Type;

/**
 * Narrow runtime support seam for residual message-level FCP operations.
 *
 * <p>This contract gives the remaining message handlers in {@code clients.fcp} a small, explicit
 * surface for runtime-dependent work that used to reach directly into {@link
 * network.crypta.node.NodeClientCore}. Typical callers get the adapter from {@link
 * FCPServer#messageRuntimeSupport()} and immediately delegate one operation such as peer lookup,
 * shutdown, or probe startup while keeping protocol branching in the message class itself.
 *
 * <p>The interface remains owned by the FCP package even though the remaining core-backed
 * implementation now lives under runtime bootstrap wiring. It is public only so that runtime-owned
 * adapters can implement it from outside {@code clients.fcp}. It is not part of {@code
 * runtime-spi}, and it is not intended to become a general daemon abstraction. Its job is narrower:
 * preserve existing node behavior while removing direct core dependencies from message-level
 * execution paths, so later refactors can adjust server bootstrap and configuration seams without
 * touching protocol handlers again.
 *
 * <ul>
 *   <li>Exposes only the runtime actions still needed by residual message classes.
 *   <li>Leaves protocol validation, reply construction, and authorization with the message code.
 *   <li>Allows tests to substitute the runtime side of those operations without mocking the core.
 * </ul>
 *
 * @see FCPServer#messageRuntimeSupport()
 */
public interface FcpMessageRuntimeSupport {

  /**
   * Creates a client with the supplied message-level queue and store behavior.
   *
   * <p>Implementations should preserve the same queue-selection and store-visibility behavior that
   * message handlers historically received from the backing node core. Callers typically use this
   * when a message needs a short-lived high-level client to fetch or inspect a noderef while still
   * keeping client creation behind a package-local seam. The returned client is live and may hold
   * node resources, so callers should avoid caching it beyond the handling flow that requested it.
   *
   * @param priorityClass client priority class requested by the caller for this operation
   * @param forceDontIgnoreStore whether the caller requires explicit store-visibility behavior
   * @param forceMixedQueue whether the caller requires mixed-queue behavior for the created client
   * @return live high-level client backed by the daemon runtime and configured for the request
   */
  HighLevelSimpleClient makeClient(
      short priorityClass, boolean forceDontIgnoreStore, boolean forceMixedQueue);

  /**
   * Enables or disables feed watching for a connection handler.
   *
   * <p>This hook toggles the handler's registration with the node-side alert or feed subsystem. The
   * message layer remains responsible for parsing the {@code Enabled} flag and deciding when to
   * call this method; the adapter only performs the runtime action. Implementations may treat the
   * call as idempotent if the handler is already in the requested state, matching the underlying
   * alert manager semantics.
   *
   * @param handler active FCP connection handler whose feed registration should change
   * @param enabled whether watch mode should be enabled for the supplied handler
   */
  void watchFeeds(FCPConnectionHandler handler, boolean enabled);

  /**
   * Requests a node shutdown with the supplied reason.
   *
   * <p>Callers invoke this only after message-level authorization and reply ordering have already
   * been handled. The adapter therefore performs the runtime shutdown action itself and should pass
   * the supplied reason through unchanged so daemon logs and lifecycle reporting continue to show
   * the same shutdown cause text as before the seam was introduced.
   *
   * @param reason shutdown reason passed through to the node lifecycle machinery
   */
  void shutdownNode(String reason);

  /**
   * Resolves a peer node by its FCP node identifier.
   *
   * <p>This lookup is used by message handlers that still need node-level peer routing decisions
   * but should no longer navigate from the server into the core and network objects directly. A
   * {@code null} result indicates that no matching peer is currently known and lets the caller keep
   * its existing protocol behavior for unknown-node replies.
   *
   * @param nodeIdentifier peer identifier supplied by the inbound message
   * @return matching peer node, or {@code null} when the identifier is not currently known
   */
  PeerNode findPeer(String nodeIdentifier);

  /**
   * Starts a probe request using the live node network subsystem.
   *
   * <p>The adapter is responsible only for handing the already-validated probe request off to the
   * runtime. Message code remains responsible for access checks, UID generation, and translating
   * listener callbacks back into FCP replies. Implementations should begin the probe with the same
   * hop limit, UID, and probe type supplied by the caller, then forward completion and error events
   * to the provided listener using the runtime's normal asynchronous behavior.
   *
   * @param hopsToLive probe hop limit to submit to the node network
   * @param uid probe UID chosen by the caller for correlation and reply matching
   * @param probeType probe type to execute against the live network
   * @param listener callback listener that receives probe results and failures
   */
  void startProbe(byte hopsToLive, long uid, Type probeType, Listener listener);
}
