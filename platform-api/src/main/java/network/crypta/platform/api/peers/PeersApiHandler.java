package network.crypta.platform.api.peers;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.json.PlatformApiFieldSetJson;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.UnknownPeerException;

/**
 * Read-only peer endpoint family for Platform API v1.
 *
 * <p>The handler maps detached peer snapshots onto nested JSON objects and preserves the runtime
 * distinction between malformed requests and a peer lookup that simply does not resolve.
 */
public final class PeersApiHandler {
  /** Detached runtime port that supplies peer lists and individual peer snapshots. */
  private final PeerPort peerPort;

  /**
   * Creates a peer API handler backed by the supplied runtime port.
   *
   * @param peerPort detached runtime peer port
   */
  public PeersApiHandler(PeerPort peerPort) {
    this.peerPort = Objects.requireNonNull(peerPort, "peerPort");
  }

  /**
   * Lists peers as JSON-compatible nested objects.
   *
   * <p>When the query parameters are omitted, both optional export flags default to {@code false}
   * to keep the initial platform surface conservative and read-only.
   *
   * @param queryParameters decoded query parameters for the current request
   * @return peer list in encounter order
   */
  public List<Map<String, Object>> list(Map<String, List<String>> queryParameters) {
    boolean includeMetadata =
        PlatformApiParameters.readBoolean(queryParameters, "includeMetadata", false);
    boolean includeVolatile =
        PlatformApiParameters.readBoolean(queryParameters, "includeVolatile", false);
    return peerPort.list(includeMetadata, includeVolatile).stream()
        .map(snapshot -> PlatformApiFieldSetJson.toJson(snapshot.root()))
        .toList();
  }

  /**
   * Resolves one peer and returns it as a JSON-compatible nested object.
   *
   * <p>When the query parameters are omitted, both optional export flags default to {@code false}
   * to keep the initial platform surface conservative and read-only.
   *
   * @param nodeIdentifier detached peer identifier extracted from the request path
   * @param queryParameters decoded query parameters for the current request
   * @return JSON-compatible peer object
   */
  public Map<String, Object> get(String nodeIdentifier, Map<String, List<String>> queryParameters) {
    boolean includeMetadata =
        PlatformApiParameters.readBoolean(queryParameters, "includeMetadata", false);
    boolean includeVolatile =
        PlatformApiParameters.readBoolean(queryParameters, "includeVolatile", false);
    try {
      return PlatformApiFieldSetJson.toJson(
          peerPort.get(nodeIdentifier, includeMetadata, includeVolatile).root());
    } catch (UnknownPeerException _) {
      throw new PlatformApiException(404, "unknown_peer", "Peer not found.");
    }
  }
}
