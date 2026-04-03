package network.crypta.platform.api.node;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.json.PlatformApiFieldSetJson;
import network.crypta.runtime.spi.NodeGreetingSnapshot;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.NodeReferenceView;

/**
 * Read-only node-info endpoint family for Platform API v1.
 *
 * <p>This handler exposes the detached node greeting and node-reference exports already provided by
 * {@link NodeInfoPort}. Query parsing and JSON mapping stay local so the router can remain focused
 * on path dispatch.
 */
public final class NodeApiHandler {
  /** Detached runtime port that supplies node greeting and node-reference exports. */
  private final NodeInfoPort nodeInfoPort;

  /**
   * Creates a node-info API handler backed by the supplied runtime port.
   *
   * @param nodeInfoPort detached runtime node-info port
   */
  public NodeApiHandler(NodeInfoPort nodeInfoPort) {
    this.nodeInfoPort = Objects.requireNonNull(nodeInfoPort, "nodeInfoPort");
  }

  /**
   * Returns the detached greeting snapshot as a JSON-compatible object.
   *
   * @return JSON-compatible greeting object
   */
  public Map<String, Object> greeting() {
    NodeGreetingSnapshot snapshot = nodeInfoPort.greeting();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("nodeName", snapshot.nodeName());
    json.put("versionString", snapshot.versionString());
    json.put("buildNumber", snapshot.buildNumber());
    json.put("revision", snapshot.revision());
    json.put("testnetEnabled", snapshot.testnetEnabled());
    json.put("compressionCodecs", snapshot.compressionCodecs());
    json.put("nodeLanguage", snapshot.nodeLanguage());
    return json;
  }

  /**
   * Returns one node-reference export as a nested JSON object.
   *
   * @param queryParameters decoded query parameters for the current request
   * @return JSON-compatible node-reference export
   */
  public Map<String, Object> reference(Map<String, List<String>> queryParameters) {
    NodeReferenceView view =
        PlatformApiParameters.requireEnum(queryParameters, "view", NodeReferenceView.class);
    boolean includeVolatile =
        PlatformApiParameters.readBoolean(queryParameters, "includeVolatile", false);
    return PlatformApiFieldSetJson.toJson(
        nodeInfoPort.exportReference(view, includeVolatile).root());
  }
}
