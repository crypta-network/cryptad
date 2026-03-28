package network.crypta.runtime.endpoints.fcp;

import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.FcpMessageRuntimeSupport;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PeerNode;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Type;

/**
 * Core-backed implementation of {@link FcpMessageRuntimeSupport}.
 *
 * <p>This adapter wraps a live {@link NodeClientCore} and translates the small message-runtime
 * contract back into the concrete daemon operations that FCP handlers already relied on before the
 * seam existed. It is deliberately thin: it keeps no additional state beyond the retained core
 * reference, performs no protocol branching of its own, and delegates each call immediately to the
 * same node services that message classes previously navigated to directly.
 *
 * <p>That design keeps the cleanup reversible and behavior-preserving. {@link FCPServer} owns one
 * adapter instance and shares it with message handlers, while tests can substitute the interface
 * instead of mocking the entire core graph. The adapter should therefore remain focused on direct
 * delegation rather than becoming a second policy layer.
 *
 * <ul>
 *   <li>Preserves existing core-backed semantics for client creation and peer lookups.
 *   <li>Delegates feed watching and shutdown to the same node subsystems used before the refactor.
 *   <li>Starts probes through the live network path without changing UID or callback handling.
 * </ul>
 *
 * @param core live daemon core backing the FCP message paths
 */
record CoreFcpMessageRuntimeSupport(NodeClientCore core) implements FcpMessageRuntimeSupport {

  /**
   * Creates a message-runtime adapter backed by the supplied node core.
   *
   * <p>The adapter keeps the reference for its full lifetime and assumes the caller has already
   * chosen the correct core instance for the surrounding {@link FCPServer}. No defensive wrapping
   * or lifecycle management is added here because the goal is to preserve the existing runtime path
   * and only narrow how message code reaches it.
   *
   * @param core live daemon core that owns the message-level services exposed through this seam
   * @throws NullPointerException if {@code core} is {@code null} when the adapter is created
   */
  CoreFcpMessageRuntimeSupport(NodeClientCore core) {
    this.core = Objects.requireNonNull(core);
  }

  /**
   * Creates a high-level client through the retained node core.
   *
   * <p>This implementation forwards directly to {@link NodeClientCore#makeClient(short, boolean,
   * boolean)} so message handlers receive the same priority, store, and queue behavior they used
   * before the adapter existed. The method adds no caching or wrapping; it simply returns the live
   * client created by the underlying core for the current request path.
   *
   * @param priorityClass client priority class requested by the message handler
   * @param forceDontIgnoreStore whether store-visibility behavior should be forced on the client
   * @param forceMixedQueue whether mixed-queue behavior should be forced on the client
   * @return live high-level client created by the retained node core
   */
  @Override
  public HighLevelSimpleClient makeClient(
      short priorityClass, boolean forceDontIgnoreStore, boolean forceMixedQueue) {
    return core.makeClient(priorityClass, forceDontIgnoreStore, forceMixedQueue);
  }

  /**
   * Toggles feed watching through the core's alert manager.
   *
   * <p>Enabling registers the supplied handler for feed events, while disabling removes it. The
   * method deliberately mirrors the previous direct message-to-core behavior and leaves any
   * idempotency or duplicate-registration handling to the alert manager implementation already used
   * by the daemon.
   *
   * @param handler active connection handler whose feed registration should change
   * @param enabled whether the handler should be registered or unregistered for feed updates
   */
  @Override
  public void watchFeeds(FCPConnectionHandler handler, boolean enabled) {
    if (enabled) {
      core.getAlerts().watch(new FcpUserAlertFeedSubscriber(handler));
    } else {
      core.getAlerts().unwatch(new FcpUserAlertFeedSubscriber(handler));
    }
  }

  /**
   * Requests node shutdown through the retained core.
   *
   * <p>The implementation delegates to the live node owned by the core and passes the supplied
   * reason string through unchanged. That preserves the shutdown cause text already expected by
   * logs, tests, and message handlers that send the protocol reply before triggering the runtime
   * exit path.
   *
   * @param reason shutdown reason to pass through to the node lifecycle
   */
  @Override
  public void shutdownNode(String reason) {
    core.getNode().exit(reason);
  }

  /**
   * Resolves a peer from the node network reachable through the retained core.
   *
   * <p>No caching or translation is added here. Callers observe the current peer table at the time
   * of the lookup and receive {@code null} when the identifier is unknown, allowing message code to
   * preserve its existing unknown-peer and darknet-only protocol behavior.
   *
   * @param nodeIdentifier peer identifier supplied by the message handler
   * @return matching peer node, or {@code null} when no current peer matches the identifier
   */
  @Override
  public PeerNode findPeer(String nodeIdentifier) {
    return core.getNode().network().getPeerNode(nodeIdentifier);
  }

  /**
   * Starts a probe through the node network associated with the retained core.
   *
   * <p>The adapter does not alter probe parameters, generate IDs, or wrap callbacks. It simply
   * passes the validated hop limit, UID, probe type, and listener to the same runtime path that
   * message handlers previously called directly, preserving asynchronous probe execution semantics.
   *
   * @param hopsToLive probe hop limit to submit to the network
   * @param uid probe UID selected by the caller for correlation
   * @param probeType probe type to execute
   * @param listener callback listener that receives probe results and failures
   */
  @Override
  public void startProbe(byte hopsToLive, long uid, Type probeType, Listener listener) {
    core.getNode().network().startProbe(hopsToLive, uid, probeType, listener);
  }
}
