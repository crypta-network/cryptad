package network.crypta.platform.api.connectivity;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.runtime.spi.ConnectivityGapSnapshot;
import network.crypta.runtime.spi.ConnectivityListenerPortSnapshot;
import network.crypta.runtime.spi.ConnectivityNoticeSnapshot;
import network.crypta.runtime.spi.ConnectivityPort;
import network.crypta.runtime.spi.ConnectivitySnapshot;
import network.crypta.runtime.spi.ConnectivitySocketSnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficEntrySnapshot;

/**
 * Read-only connectivity endpoint family for Platform API v1.
 *
 * <p>The handler reuses the cost boundary already present in {@link ConnectivityPort}: callers must
 * explicitly request advanced details, otherwise the API returns only the summary snapshot.
 */
public final class ConnectivityApiHandler {
  /** Detached runtime port that supplies connectivity snapshots for the API layer. */
  private final ConnectivityPort connectivityPort;

  /**
   * Creates a connectivity API handler backed by the supplied runtime port.
   *
   * @param connectivityPort detached runtime connectivity port
   */
  public ConnectivityApiHandler(ConnectivityPort connectivityPort) {
    this.connectivityPort = Objects.requireNonNull(connectivityPort, "connectivityPort");
  }

  /**
   * Exports one connectivity snapshot.
   *
   * @param queryParameters decoded query parameters for the current request
   * @return JSON-compatible connectivity snapshot
   */
  public Map<String, Object> snapshot(Map<String, List<String>> queryParameters) {
    boolean includeAdvanced = PlatformApiParameters.readBoolean(queryParameters, "advanced", false);
    ConnectivitySnapshot snapshot = connectivityPort.snapshot(includeAdvanced);

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("darknetFnpPort", snapshot.darknetFnpPort());
    json.put("opennetFnpPort", snapshot.opennetFnpPort());
    json.put("fproxyListener", toJson(snapshot.fproxyListener()));
    json.put("fcpListener", toJson(snapshot.fcpListener()));
    json.put("consoleListener", toJson(snapshot.consoleListener()));
    json.put("connectionTypeNotice", toJson(snapshot.connectionTypeNotice()));
    json.put("sockets", snapshot.sockets().stream().map(ConnectivityApiHandler::toJson).toList());
    return json;
  }

  /**
   * Converts one listener-port snapshot into a JSON-compatible object.
   *
   * @param snapshot detached runtime listener snapshot
   * @return JSON-compatible listener representation
   */
  private static Map<String, Object> toJson(ConnectivityListenerPortSnapshot snapshot) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("enabled", snapshot.enabled());
    json.put("port", snapshot.port());
    return json;
  }

  /**
   * Converts one optional connectivity notice into a JSON-compatible object.
   *
   * @param snapshot detached runtime notice snapshot, or {@code null} when no notice is present
   * @return JSON-compatible notice representation, or an empty object when the notice is absent
   */
  private static Map<String, Object> toJson(ConnectivityNoticeSnapshot snapshot) {
    if (snapshot == null) {
      return Map.of();
    }
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("title", snapshot.title());
    json.put("text", snapshot.text());
    json.put("renderedAlertHtml", snapshot.renderedAlertHtml());
    return json;
  }

  /**
   * Converts one socket snapshot into a JSON-compatible object.
   *
   * @param snapshot detached runtime socket snapshot
   * @return JSON-compatible socket representation
   */
  private static Map<String, Object> toJson(ConnectivitySocketSnapshot snapshot) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put("title", snapshot.title());
    json.put("portForwardStatus", snapshot.portForwardStatus().name());
    json.put("longestSendReceiveGapMillis", snapshot.longestSendReceiveGapMillis());
    json.put("peerEntries", toJson(snapshot.peerEntries()));
    json.put("ipEntries", toJson(snapshot.ipEntries()));
    return json;
  }

  /**
   * Converts a connectivity traffic-entry list into JSON-compatible objects.
   *
   * @param entries detached runtime traffic-entry snapshots in encounter order
   * @return JSON-compatible traffic-entry objects in encounter order
   */
  private static List<Map<String, Object>> toJson(List<ConnectivityTrafficEntrySnapshot> entries) {
    return entries.stream().map(ConnectivityApiHandler::toJson).toList();
  }

  /**
   * Converts one traffic entry into a JSON-compatible object.
   *
   * @param snapshot detached runtime traffic-entry snapshot
   * @return JSON-compatible traffic-entry representation
   */
  private static Map<String, Object> toJson(ConnectivityTrafficEntrySnapshot snapshot) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("address", snapshot.address());
    json.put("packetsSent", snapshot.packetsSent());
    json.put("packetsReceived", snapshot.packetsReceived());
    json.put("initiator", snapshot.initiator().name());
    json.put("firstSendLeadTimeMillis", snapshot.firstSendLeadTimeMillis());
    json.put("firstReceiveLeadTimeMillis", snapshot.firstReceiveLeadTimeMillis());
    json.put("gaps", snapshot.gaps().stream().map(ConnectivityApiHandler::toJson).toList());
    return json;
  }

  /**
   * Converts one receive-gap snapshot into a JSON-compatible object.
   *
   * @param snapshot detached runtime gap snapshot
   * @return JSON-compatible gap representation
   */
  private static Map<String, Object> toJson(ConnectivityGapSnapshot snapshot) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("gapLengthMillis", snapshot.gapLengthMillis());
    json.put("receivedPacketAtMillis", snapshot.receivedPacketAtMillis());
    return json;
  }
}
