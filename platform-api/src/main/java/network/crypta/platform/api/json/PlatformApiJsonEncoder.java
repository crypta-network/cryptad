package network.crypta.platform.api.json;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.runtime.spi.ConfigFieldSet;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;
import network.crypta.runtime.spi.ConnectivityGapSnapshot;
import network.crypta.runtime.spi.ConnectivityListenerPortSnapshot;
import network.crypta.runtime.spi.ConnectivityNoticeSnapshot;
import network.crypta.runtime.spi.ConnectivitySnapshot;
import network.crypta.runtime.spi.ConnectivitySocketSnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficEntrySnapshot;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeGreetingSnapshot;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;

/**
 * DTO-to-JSON encoders for the Platform API response surface.
 *
 * <p>These helpers map detached runtime SPI DTOs into compact JSON objects and arrays using only
 * JDK types plus the minimal {@link PlatformApiJsonWriter}. Nested field-set trees are rendered as
 * plain JSON objects that preserve the encounter order of direct values and direct child subsets.
 */
public final class PlatformApiJsonEncoder {
  /** Shared null-check label used for snapshot-based encoders. */
  private static final String SNAPSHOT = "snapshot";

  /** Prevents instantiation of this static helper type. */
  private PlatformApiJsonEncoder() {}

  /**
   * Encodes one node-greeting snapshot as JSON.
   *
   * @param snapshot detached runtime snapshot to encode
   * @return compact JSON representation
   */
  @SuppressWarnings("unused")
  public static String encodeNodeGreeting(NodeGreetingSnapshot snapshot) {
    Objects.requireNonNull(snapshot, SNAPSHOT);

    LinkedHashMap<String, Object> object = LinkedHashMap.newLinkedHashMap(7);
    object.put("nodeName", snapshot.nodeName());
    object.put("versionString", snapshot.versionString());
    object.put("buildNumber", snapshot.buildNumber());
    object.put("revision", snapshot.revision());
    object.put("testnetEnabled", snapshot.testnetEnabled());
    object.put("compressionCodecs", snapshot.compressionCodecs());
    object.put("nodeLanguage", snapshot.nodeLanguage());
    return PlatformApiJsonWriter.write(object);
  }

  /**
   * Encodes one node-reference snapshot as JSON.
   *
   * @param snapshot detached runtime snapshot to encode
   * @return compact JSON representation
   */
  public static String encodeNodeReference(NodeReferenceSnapshot snapshot) {
    Objects.requireNonNull(snapshot, SNAPSHOT);
    return PlatformApiJsonWriter.write(encodeNodeFieldSet(snapshot.root()));
  }

  /**
   * Encodes one peer snapshot as JSON.
   *
   * @param snapshot detached runtime snapshot to encode
   * @return compact JSON representation
   */
  @SuppressWarnings("unused")
  public static String encodePeer(PeerSnapshot snapshot) {
    Objects.requireNonNull(snapshot, SNAPSHOT);
    return PlatformApiJsonWriter.write(encodePeerFieldSet(snapshot.root()));
  }

  /**
   * Encodes a peer snapshot list as JSON.
   *
   * @param snapshots detached runtime snapshots in encounter order
   * @return compact JSON array representation
   */
  @SuppressWarnings("unused")
  public static String encodePeers(List<PeerSnapshot> snapshots) {
    Objects.requireNonNull(snapshots, "snapshots");
    return PlatformApiJsonWriter.write(
        snapshots.stream()
            .map(PeerSnapshot::root)
            .map(PlatformApiJsonEncoder::encodePeerFieldSet)
            .toList());
  }

  /**
   * Encodes one configuration snapshot as JSON.
   *
   * @param snapshot detached runtime snapshot to encode
   * @return compact JSON representation
   */
  public static String encodeConfig(ConfigSnapshot snapshot) {
    Objects.requireNonNull(snapshot, SNAPSHOT);

    LinkedHashMap<String, Object> object =
        LinkedHashMap.newLinkedHashMap(snapshot.sections().size());
    for (Map.Entry<ConfigSection, ConfigFieldSet> entry : snapshot.sections().entrySet()) {
      object.put(entry.getKey().name(), encodeConfigFieldSet(entry.getValue()));
    }
    return PlatformApiJsonWriter.write(object);
  }

  /**
   * Encodes one connectivity snapshot as JSON.
   *
   * @param snapshot detached runtime snapshot to encode
   * @return compact JSON representation
   */
  @SuppressWarnings("unused")
  public static String encodeConnectivity(ConnectivitySnapshot snapshot) {
    Objects.requireNonNull(snapshot, SNAPSHOT);

    LinkedHashMap<String, Object> object = LinkedHashMap.newLinkedHashMap(7);
    object.put("darknetFnpPort", snapshot.darknetFnpPort());
    object.put("opennetFnpPort", snapshot.opennetFnpPort());
    object.put("fproxyListener", encodeConnectivityListener(snapshot.fproxyListener()));
    object.put("fcpListener", encodeConnectivityListener(snapshot.fcpListener()));
    object.put("consoleListener", encodeConnectivityListener(snapshot.consoleListener()));
    object.put(
        "connectionTypeNotice",
        snapshot.connectionTypeNotice() == null
            ? null
            : encodeConnectivityNotice(snapshot.connectionTypeNotice()));
    object.put(
        "sockets",
        snapshot.sockets().stream().map(PlatformApiJsonEncoder::encodeConnectivitySocket).toList());
    return PlatformApiJsonWriter.write(object);
  }

  /**
   * Encodes one security-levels snapshot as JSON.
   *
   * @param snapshot detached runtime snapshot to encode
   * @return compact JSON representation
   */
  @SuppressWarnings("unused")
  public static String encodeSecurityLevels(SecurityLevelsSnapshot snapshot) {
    Objects.requireNonNull(snapshot, SNAPSHOT);

    LinkedHashMap<String, Object> object = LinkedHashMap.newLinkedHashMap(5);
    object.put("networkThreatLevel", snapshot.networkThreatLevel().name());
    object.put("physicalThreatLevel", snapshot.physicalThreatLevel().name());
    object.put("hasDatabase", snapshot.hasDatabase());
    object.put("masterPasswordFileExists", snapshot.masterPasswordFileExists());
    object.put("masterPasswordFilePath", snapshot.masterPasswordFilePath());
    return PlatformApiJsonWriter.write(object);
  }

  /**
   * Encodes a standard Platform API error body as JSON.
   *
   * @param code stable machine-readable error code
   * @param message human-readable error message
   * @return compact JSON representation
   */
  public static String encodeError(String code, String message) {
    Objects.requireNonNull(code, "code");
    Objects.requireNonNull(message, "message");

    LinkedHashMap<String, Object> error = LinkedHashMap.newLinkedHashMap(2);
    error.put("code", code);
    error.put("message", message);

    LinkedHashMap<String, Object> object = LinkedHashMap.newLinkedHashMap(1);
    object.put("error", error);
    return PlatformApiJsonWriter.write(object);
  }

  /**
   * Encodes a node field-set tree as a nested JSON object.
   *
   * @param fieldSet detached runtime node field-set tree
   * @return encounter-order-preserving nested JSON object representation
   */
  private static Map<String, Object> encodeNodeFieldSet(NodeFieldSet fieldSet) {
    return encodeFieldSet(
        fieldSet.directValues(),
        fieldSet.directSubsets(),
        PlatformApiJsonEncoder::encodeNodeFieldSet);
  }

  /**
   * Encodes a peer field-set tree as a nested JSON object.
   *
   * @param fieldSet detached runtime peer field-set tree
   * @return encounter-order-preserving nested JSON object representation
   */
  private static Map<String, Object> encodePeerFieldSet(PeerFieldSet fieldSet) {
    return encodeFieldSet(
        fieldSet.directValues(),
        fieldSet.directSubsets(),
        PlatformApiJsonEncoder::encodePeerFieldSet);
  }

  /**
   * Encodes a configuration field-set tree as a nested JSON object.
   *
   * @param fieldSet detached runtime configuration field-set tree
   * @return encounter-order-preserving nested JSON object representation
   */
  private static Map<String, Object> encodeConfigFieldSet(ConfigFieldSet fieldSet) {
    return encodeFieldSet(
        fieldSet.directValues(),
        fieldSet.directSubsets(),
        PlatformApiJsonEncoder::encodeConfigFieldSet);
  }

  /**
   * Encodes one generic field-set tree as a nested JSON object.
   *
   * @param directValues direct scalar values at the current tree level
   * @param directSubsets child subsets keyed by field-set name
   * @param subsetEncoder encoder used for recursive child-subset mapping
   * @return encounter-order-preserving nested JSON object representation
   * @param <T> child subset type
   */
  private static <T> Map<String, Object> encodeFieldSet(
      Map<String, String> directValues,
      Map<String, T> directSubsets,
      java.util.function.Function<T, Map<String, Object>> subsetEncoder) {
    LinkedHashMap<String, Object> object =
        LinkedHashMap.newLinkedHashMap(directValues.size() + directSubsets.size());
    object.putAll(directValues);
    directSubsets.forEach((name, subset) -> object.put(name, subsetEncoder.apply(subset)));
    return object;
  }

  /**
   * Encodes one connectivity listener snapshot as a JSON object.
   *
   * @param snapshot detached runtime listener snapshot
   * @return JSON-compatible listener representation
   */
  private static Map<String, Object> encodeConnectivityListener(
      ConnectivityListenerPortSnapshot snapshot) {
    LinkedHashMap<String, Object> object = LinkedHashMap.newLinkedHashMap(2);
    object.put("enabled", snapshot.enabled());
    object.put("port", snapshot.port());
    return object;
  }

  /**
   * Encodes one connectivity notice snapshot as a JSON object.
   *
   * @param snapshot detached runtime notice snapshot
   * @return JSON-compatible notice representation
   */
  private static Map<String, Object> encodeConnectivityNotice(ConnectivityNoticeSnapshot snapshot) {
    LinkedHashMap<String, Object> object = LinkedHashMap.newLinkedHashMap(3);
    object.put("title", snapshot.title());
    object.put("text", snapshot.text());
    object.put("renderedAlertHtml", snapshot.renderedAlertHtml());
    return object;
  }

  /**
   * Encodes one connectivity socket snapshot as a JSON object.
   *
   * @param snapshot detached runtime socket snapshot
   * @return JSON-compatible socket representation
   */
  private static Map<String, Object> encodeConnectivitySocket(ConnectivitySocketSnapshot snapshot) {
    LinkedHashMap<String, Object> object = LinkedHashMap.newLinkedHashMap(5);
    object.put("title", snapshot.title());
    object.put("portForwardStatus", snapshot.portForwardStatus().name());
    object.put("longestSendReceiveGapMillis", snapshot.longestSendReceiveGapMillis());
    object.put(
        "peerEntries",
        snapshot.peerEntries().stream()
            .map(PlatformApiJsonEncoder::encodeConnectivityTrafficEntry)
            .toList());
    object.put(
        "ipEntries",
        snapshot.ipEntries().stream()
            .map(PlatformApiJsonEncoder::encodeConnectivityTrafficEntry)
            .toList());
    return object;
  }

  /**
   * Encodes one connectivity traffic entry as a JSON object.
   *
   * @param snapshot detached runtime traffic-entry snapshot
   * @return JSON-compatible traffic-entry representation
   */
  private static Map<String, Object> encodeConnectivityTrafficEntry(
      ConnectivityTrafficEntrySnapshot snapshot) {
    LinkedHashMap<String, Object> object = LinkedHashMap.newLinkedHashMap(7);
    object.put("address", snapshot.address());
    object.put("packetsSent", snapshot.packetsSent());
    object.put("packetsReceived", snapshot.packetsReceived());
    object.put("initiator", snapshot.initiator().name());
    object.put("firstSendLeadTimeMillis", snapshot.firstSendLeadTimeMillis());
    object.put("firstReceiveLeadTimeMillis", snapshot.firstReceiveLeadTimeMillis());
    object.put(
        "gaps",
        snapshot.gaps().stream().map(PlatformApiJsonEncoder::encodeConnectivityGap).toList());
    return object;
  }

  /**
   * Encodes one connectivity gap snapshot as a JSON object.
   *
   * @param snapshot detached runtime gap snapshot
   * @return JSON-compatible gap representation
   */
  private static Map<String, Object> encodeConnectivityGap(ConnectivityGapSnapshot snapshot) {
    LinkedHashMap<String, Object> object = LinkedHashMap.newLinkedHashMap(2);
    object.put("gapLengthMillis", snapshot.gapLengthMillis());
    object.put("receivedPacketAtMillis", snapshot.receivedPacketAtMillis());
    return object;
  }
}
