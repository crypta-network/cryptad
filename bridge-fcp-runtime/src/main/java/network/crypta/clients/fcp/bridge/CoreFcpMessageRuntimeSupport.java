package network.crypta.clients.fcp.bridge;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.util.Objects;
import network.crypta.client.FetchException;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.ContentFilterCallbacks;
import network.crypta.client.filter.ContentFilterRequest;
import network.crypta.client.filter.UnsafeContentTypeException;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.FcpDarknetPeerHandle;
import network.crypta.clients.fcp.FcpFilterResult;
import network.crypta.clients.fcp.FcpMessageRuntimeSupport;
import network.crypta.clients.fcp.FcpPeerLookupResult;
import network.crypta.clients.fcp.FcpPeerReferenceFetchException;
import network.crypta.clients.fcp.FcpProbeError;
import network.crypta.clients.fcp.FcpProbeListener;
import network.crypta.clients.fcp.FcpProbeType;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PeerNode;
import network.crypta.node.probe.Error;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Type;
import network.crypta.runtime.peers.reference.PeerReferenceTextLoader;

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
 *   <li>Preserves existing core-backed semantics for peer-reference loading and peer lookups.
 *   <li>Delegates feed watching and shutdown to the same node subsystems used before the refactor.
 *   <li>Maps adapter-owned peer and probe seam types back to the live node runtime types.
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

  @Override
  public StringBuilder readPeerReferenceFromUrl(URL url) throws IOException {
    return PeerReferenceTextLoader.readFromUrl(url);
  }

  @Override
  public StringBuilder readPeerReferenceFromCryptaUri(
      FreenetURI uri, short priorityClass, boolean forceDontIgnoreStore, boolean forceMixedQueue)
      throws IOException, FcpPeerReferenceFetchException {
    try {
      return PeerReferenceTextLoader.readFromFreenetUri(
          uri, core.makeClient(priorityClass, forceDontIgnoreStore, forceMixedQueue));
    } catch (FetchException e) {
      throw new FcpPeerReferenceFetchException("Failed to fetch peer reference from Crypta URI", e);
    }
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

  @Override
  public FcpFilterResult filterContent(
      InputStream input, OutputStream output, String mimeType, URI fakeUri) throws IOException {
    ContentFilterRequest request =
        new ContentFilterRequest(input, output, mimeType, null, null, null);
    ContentFilterCallbacks callbacks =
        new ContentFilterCallbacks(
            fakeUri, null, null, core.getClientContext().linkFilterExceptionProvider);
    try {
      ContentFilter.FilterStatus status = ContentFilter.filter(request, callbacks);
      return FcpFilterResult.safe(status.charset, status.mimeType);
    } catch (UnsafeContentTypeException _) {
      return FcpFilterResult.unsafe();
    }
  }

  /**
   * Resolves a peer from the node network reachable through the retained core.
   *
   * <p>No caching or translation is added here. Callers observe the current peer table at the time
   * of the lookup and receive an adapter-owned result describing whether the peer is unknown,
   * non-darknet, or a valid darknet target. That keeps message-layer branching behavior unchanged
   * while preventing runtime peer types from leaking back into {@code :adapter-fcp}.
   *
   * @param nodeIdentifier peer identifier supplied by the message handler
   * @return adapter-owned lookup result describing the current peer state
   */
  @Override
  public FcpPeerLookupResult findPeer(String nodeIdentifier) {
    PeerNode peerNode = core.getNode().network().getPeerNode(nodeIdentifier);
    if (peerNode == null) {
      return FcpPeerLookupResult.unknown();
    }
    if (peerNode instanceof DarknetPeerNode darknetPeerNode) {
      return FcpPeerLookupResult.darknet(new CoreFcpDarknetPeerHandle(darknetPeerNode));
    }
    return FcpPeerLookupResult.nonDarknet();
  }

  /**
   * Starts a probe through the node network associated with the retained core.
   *
   * <p>The adapter does not alter probe parameters or generate IDs. It maps the adapter-owned probe
   * type and listener back to the runtime probe equivalents, then delegates to the same network
   * path that message handlers previously called directly. That preserves asynchronous probe
   * execution semantics while keeping the runtime probe package out of {@code :adapter-fcp}.
   *
   * @param hopsToLive probe hop limit to submit to the network
   * @param uid probe UID selected by the caller for correlation
   * @param probeType adapter-owned probe type to execute
   * @param listener adapter-owned callback listener that receives probe results and failures
   */
  @Override
  public void startProbe(
      byte hopsToLive, long uid, FcpProbeType probeType, FcpProbeListener listener) {
    core.getNode()
        .network()
        .startProbe(hopsToLive, uid, toRuntimeProbeType(probeType), toRuntimeListener(listener));
  }

  private static Type toRuntimeProbeType(FcpProbeType probeType) {
    return switch (probeType) {
      case BANDWIDTH -> Type.BANDWIDTH;
      case BUILD -> Type.BUILD;
      case IDENTIFIER -> Type.IDENTIFIER;
      case LINK_LENGTHS -> Type.LINK_LENGTHS;
      case LOCATION -> Type.LOCATION;
      case STORE_SIZE -> Type.STORE_SIZE;
      case UPTIME_48H -> Type.UPTIME_48H;
      case UPTIME_7D -> Type.UPTIME_7D;
      case REJECT_STATS -> Type.REJECT_STATS;
      case OVERALL_BULK_OUTPUT_CAPACITY_USAGE -> Type.OVERALL_BULK_OUTPUT_CAPACITY_USAGE;
    };
  }

  private static FcpProbeError toAdapterProbeError(Error error) {
    return switch (error) {
      case DISCONNECTED -> FcpProbeError.DISCONNECTED;
      case OVERLOAD -> FcpProbeError.OVERLOAD;
      case TIMEOUT -> FcpProbeError.TIMEOUT;
      case UNKNOWN -> FcpProbeError.UNKNOWN;
      case UNRECOGNIZED_TYPE -> FcpProbeError.UNRECOGNIZED_TYPE;
      case CANNOT_FORWARD -> FcpProbeError.CANNOT_FORWARD;
    };
  }

  private static Listener toRuntimeListener(FcpProbeListener listener) {
    Objects.requireNonNull(listener);
    return new Listener() {
      @Override
      public void onError(Error error, Byte code, boolean local) {
        listener.onError(toAdapterProbeError(error), code, local);
      }

      @Override
      public void onRefused() {
        listener.onRefused();
      }

      @Override
      public void onOutputBandwidth(float outputBandwidth) {
        listener.onOutputBandwidth(outputBandwidth);
      }

      @Override
      public void onBuild(int build) {
        listener.onBuild(build);
      }

      @Override
      public void onIdentifier(long probeIdentifier, byte percentageUptime) {
        listener.onIdentifier(probeIdentifier, percentageUptime);
      }

      @Override
      public void onLinkLengths(float[] linkLengths) {
        listener.onLinkLengths(linkLengths);
      }

      @Override
      public void onLocation(float location) {
        listener.onLocation(location);
      }

      @Override
      public void onStoreSize(float storeSize) {
        listener.onStoreSize(storeSize);
      }

      @Override
      public void onUptime(float uptimePercent) {
        listener.onUptime(uptimePercent);
      }

      @Override
      public void onRejectStats(byte[] stats) {
        listener.onRejectStats(stats);
      }

      @Override
      public void onOverallBulkOutputCapacity(
          byte bandwidthClassForCapacityUsage, float capacityUsage) {
        listener.onOverallBulkOutputCapacity(bandwidthClassForCapacityUsage, capacityUsage);
      }
    };
  }

  private record CoreFcpDarknetPeerHandle(DarknetPeerNode peerNode)
      implements FcpDarknetPeerHandle {

    private CoreFcpDarknetPeerHandle {
      Objects.requireNonNull(peerNode);
    }

    @Override
    public int sendTextFeed(String text) {
      return peerNode.sendTextFeed(text);
    }

    @Override
    public int sendDownloadFeed(FreenetURI uri, String description) {
      return peerNode.sendDownloadFeed(uri, description);
    }

    @Override
    public int sendBookmarkFeed(
        FreenetURI uri, String bookmarkName, String description, boolean hasAnActiveLink) {
      return peerNode.sendBookmarkFeed(uri, bookmarkName, description, hasAnActiveLink);
    }
  }
}
