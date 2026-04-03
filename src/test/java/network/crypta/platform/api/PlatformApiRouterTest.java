package network.crypta.platform.api;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.runtime.spi.ConfigFieldSet;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;
import network.crypta.runtime.spi.ConnectivityGapSnapshot;
import network.crypta.runtime.spi.ConnectivityListenerPortSnapshot;
import network.crypta.runtime.spi.ConnectivityNoticeSnapshot;
import network.crypta.runtime.spi.ConnectivityPort;
import network.crypta.runtime.spi.ConnectivityPortForwardStatus;
import network.crypta.runtime.spi.ConnectivitySnapshot;
import network.crypta.runtime.spi.ConnectivitySocketSnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficEntrySnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficInitiator;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeGreetingSnapshot;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.runtime.spi.UnknownPeerException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PlatformApiRouterTest {

  @Mock private RuntimePorts runtimePorts;
  @Mock private NodeInfoPort nodeInfoPort;
  @Mock private PeerPort peerPort;
  @Mock private ConfigPort configPort;
  @Mock private ConnectivityPort connectivityPort;
  @Mock private SecurityLevelsPort securityLevelsPort;

  private PlatformApiRouter router;

  @BeforeEach
  void setUp() {
    when(runtimePorts.nodeInfo()).thenReturn(nodeInfoPort);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(runtimePorts.config()).thenReturn(configPort);
    when(runtimePorts.connectivity()).thenReturn(connectivityPort);
    when(runtimePorts.securityLevels()).thenReturn(securityLevelsPort);
    router = new PlatformApiRouter(runtimePorts);
  }

  @Test
  void route_whenMethodNotGet_expectJson405AndAllowGetHeader() {
    PlatformApiResponse response =
        router.route(request("POST", List.of("node", "greeting"), Map.of()));

    assertEquals(405, response.statusCode());
    assertEquals("Method Not Allowed", response.reasonPhrase());
    assertEquals(Map.of("Allow", "GET"), response.headers());
    assertEquals(
        "{\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Platform API v1 supports GET"
            + " requests only.\"}}",
        response.body());
  }

  @Test
  void route_whenNodeGreetingRequest_expectGreetingJson() {
    when(nodeInfoPort.greeting())
        .thenReturn(new NodeGreetingSnapshot("Crypta", "1.0", 7, "abc123", true, "gzip", "en"));

    PlatformApiResponse response =
        router.route(request("GET", List.of("node", "greeting"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"nodeName\":\"Crypta\",\"versionString\":\"1.0\",\"buildNumber\":7,\"revision\":\"abc123\",\"testnetEnabled\":true,\"compressionCodecs\":\"gzip\",\"nodeLanguage\":\"en\"}",
        response.body());
  }

  @Test
  void route_whenNodeReferenceRequested_expectReferenceJsonAndRequestedExport() {
    LinkedHashMap<String, String> directValues = LinkedHashMap.newLinkedHashMap(2);
    directValues.put("identity", "alpha");
    directValues.put("version", "42");
    LinkedHashMap<String, NodeFieldSet> directSubsets = LinkedHashMap.newLinkedHashMap(1);
    directSubsets.put("physical", new NodeFieldSet(Map.of("host", "127.0.0.1"), Map.of()));
    when(nodeInfoPort.exportReference(NodeReferenceView.DARKNET_PUBLIC, true))
        .thenReturn(new NodeReferenceSnapshot(new NodeFieldSet(directValues, directSubsets)));

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("node", "reference"),
                Map.of("view", List.of("DARKNET_PUBLIC"), "includeVolatile", List.of("true"))));

    verify(nodeInfoPort).exportReference(NodeReferenceView.DARKNET_PUBLIC, true);
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"identity\":\"alpha\",\"version\":\"42\",\"physical\":{\"host\":\"127.0.0.1\"}}",
        response.body());
  }

  @Test
  void route_whenNodeReferenceViewInvalid_expectBadRequestJson() {
    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("node", "reference"),
                Map.of("view", List.of("INVALID"), "includeVolatile", List.of("true"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"invalid_query_parameter\""));
    assertTrue(response.body().contains("Query parameter 'view'"));
    verifyNoInteractions(nodeInfoPort);
  }

  @Test
  void route_whenConfigSectionsInvalid_expectBadRequestJson() {
    PlatformApiResponse response =
        router.route(
            request("GET", List.of("config"), Map.of("sections", List.of("CURRENT,BOGUS"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"invalid_query_parameter\""));
    assertTrue(response.body().contains("Query parameter 'sections'"));
    verifyNoInteractions(configPort);
  }

  @Test
  void route_whenPeersListFlagsOmitted_expectPeerJsonArrayAndConservativeDefaults() {
    LinkedHashMap<String, String> directValues = LinkedHashMap.newLinkedHashMap(2);
    directValues.put("nodeIdentifier", "peer-1");
    directValues.put("status", "connected");
    LinkedHashMap<String, PeerFieldSet> directSubsets = LinkedHashMap.newLinkedHashMap(1);
    directSubsets.put("metadata", new PeerFieldSet(Map.of("location", "0.5"), Map.of()));
    when(peerPort.list(false, false))
        .thenReturn(List.of(new PeerSnapshot(new PeerFieldSet(directValues, directSubsets))));

    PlatformApiResponse response = router.route(request("GET", List.of("peers"), Map.of()));

    verify(peerPort).list(false, false);
    assertEquals(200, response.statusCode());
    assertEquals(
        "[{\"nodeIdentifier\":\"peer-1\",\"status\":\"connected\",\"metadata\":{\"location\":\"0.5\"}}]",
        response.body());
  }

  @Test
  void route_whenPeerRequested_expectPeerJsonAndRequestedFlags() throws UnknownPeerException {
    LinkedHashMap<String, String> directValues = LinkedHashMap.newLinkedHashMap(2);
    directValues.put("nodeIdentifier", "peer-2");
    directValues.put("status", "backed-off");
    LinkedHashMap<String, PeerFieldSet> directSubsets = LinkedHashMap.newLinkedHashMap(1);
    directSubsets.put("physical", new PeerFieldSet(Map.of("address", "127.0.0.1"), Map.of()));
    when(peerPort.get("peer-2", true, true))
        .thenReturn(new PeerSnapshot(new PeerFieldSet(directValues, directSubsets)));

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("peers", "peer-2"),
                Map.of("includeMetadata", List.of("true"), "includeVolatile", List.of("true"))));

    verify(peerPort).get("peer-2", true, true);
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"nodeIdentifier\":\"peer-2\",\"status\":\"backed-off\",\"physical\":{\"address\":\"127.0.0.1\"}}",
        response.body());
  }

  @Test
  void route_whenConnectivityAdvancedInvalid_expectBadRequestJson() {
    PlatformApiResponse response =
        router.route(
            request("GET", List.of("connectivity"), Map.of("advanced", List.of("sometimes"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"invalid_query_parameter\""));
    assertTrue(response.body().contains("advanced"));
    verifyNoInteractions(connectivityPort);
  }

  @Test
  void route_whenConnectivityAdvancedRequested_expectDetailedSnapshotJson() {
    when(connectivityPort.snapshot(true))
        .thenReturn(
            new ConnectivitySnapshot(
                1234,
                5678,
                new ConnectivityListenerPortSnapshot(true, 8888),
                new ConnectivityListenerPortSnapshot(false, 0),
                new ConnectivityListenerPortSnapshot(true, 9999),
                new ConnectivityNoticeSnapshot(
                    "NAT detected", "Forward UDP to improve reachability.", "<div>notice</div>"),
                List.of(
                    new ConnectivitySocketSnapshot(
                        "udp-main",
                        ConnectivityPortForwardStatus.MAYBE_PORT_FORWARDED,
                        42,
                        List.of(
                            new ConnectivityTrafficEntrySnapshot(
                                "peer-1",
                                10,
                                7,
                                ConnectivityTrafficInitiator.LOCAL,
                                3,
                                5,
                                List.of(new ConnectivityGapSnapshot(8, 13)))),
                        List.of(
                            new ConnectivityTrafficEntrySnapshot(
                                "203.0.113.5",
                                4,
                                6,
                                ConnectivityTrafficInitiator.REMOTE,
                                2,
                                1,
                                List.of()))))));

    PlatformApiResponse response =
        router.route(request("GET", List.of("connectivity"), Map.of("advanced", List.of("true"))));

    verify(connectivityPort).snapshot(true);
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"darknetFnpPort\":1234,\"opennetFnpPort\":5678,\"fproxyListener\":{\"enabled\":true,\"port\":8888},\"fcpListener\":{\"enabled\":false,\"port\":0},\"consoleListener\":{\"enabled\":true,\"port\":9999},\"connectionTypeNotice\":{\"title\":\"NAT"
            + " detected\",\"text\":\"Forward UDP to improve"
            + " reachability.\",\"renderedAlertHtml\":\"<div>notice</div>\"},\"sockets\":[{\"title\":\"udp-main\",\"portForwardStatus\":\"MAYBE_PORT_FORWARDED\",\"longestSendReceiveGapMillis\":42,\"peerEntries\":[{\"address\":\"peer-1\",\"packetsSent\":10,\"packetsReceived\":7,\"initiator\":\"LOCAL\",\"firstSendLeadTimeMillis\":3,\"firstReceiveLeadTimeMillis\":5,\"gaps\":[{\"gapLengthMillis\":8,\"receivedPacketAtMillis\":13}]}],\"ipEntries\":[{\"address\":\"203.0.113.5\",\"packetsSent\":4,\"packetsReceived\":6,\"initiator\":\"REMOTE\",\"firstSendLeadTimeMillis\":2,\"firstReceiveLeadTimeMillis\":1,\"gaps\":[]}]}]}",
        response.body());
  }

  @Test
  void route_whenConnectivityNoticeMissing_expectEmptyJsonObject() {
    when(connectivityPort.snapshot(false))
        .thenReturn(
            new ConnectivitySnapshot(
                1234,
                5678,
                new ConnectivityListenerPortSnapshot(true, 8888),
                new ConnectivityListenerPortSnapshot(false, 0),
                new ConnectivityListenerPortSnapshot(true, 9999),
                null,
                List.of(
                    new ConnectivitySocketSnapshot(
                        "udp-main",
                        ConnectivityPortForwardStatus.DONT_KNOW,
                        -1,
                        List.of(),
                        List.of()))));

    PlatformApiResponse response = router.route(request("GET", List.of("connectivity"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"darknetFnpPort\":1234,\"opennetFnpPort\":5678,\"fproxyListener\":{\"enabled\":true,\"port\":8888},\"fcpListener\":{\"enabled\":false,\"port\":0},\"consoleListener\":{\"enabled\":true,\"port\":9999},\"connectionTypeNotice\":{},\"sockets\":[{\"title\":\"udp-main\",\"portForwardStatus\":\"DONT_KNOW\",\"longestSendReceiveGapMillis\":-1,\"peerEntries\":[],\"ipEntries\":[]}]}",
        response.body());
  }

  @Test
  void route_whenSecurityLevelsRequested_expectSecurityLevelsJson() {
    when(securityLevelsPort.snapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.HIGH,
                SecurityPhysicalThreatLevel.NORMAL,
                true,
                false,
                "/var/lib/cryptad/master.keys"));

    PlatformApiResponse response =
        router.route(request("GET", List.of("security-levels"), Map.of()));

    verify(securityLevelsPort).snapshot();
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"networkThreatLevel\":\"HIGH\",\"physicalThreatLevel\":\"NORMAL\",\"hasDatabase\":true,\"masterPasswordFileExists\":false,\"masterPasswordFilePath\":\"/var/lib/cryptad/master.keys\"}",
        response.body());
  }

  @Test
  void route_whenPeerMissing_expectJson404() throws UnknownPeerException {
    when(peerPort.get("peer-1", true, false)).thenThrow(new UnknownPeerException("peer-1"));

    PlatformApiResponse response =
        router.route(
            request("GET", List.of("peers", "peer-1"), Map.of("includeMetadata", List.of("true"))));

    assertEquals(404, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"unknown_peer\",\"message\":\"Peer not found.\"}}", response.body());
  }

  @Test
  void route_whenConfigSectionsOmitted_expectCurrentSectionOnly() {
    ConfigSnapshot snapshot =
        new ConfigSnapshot(
            Map.of(
                ConfigSection.CURRENT,
                new ConfigFieldSet(
                    Map.of("enabled", "true"),
                    Map.of("node", new ConfigFieldSet(Map.of("name", "alpha"), Map.of())))));
    when(configPort.export(EnumSet.of(ConfigSection.CURRENT))).thenReturn(snapshot);

    PlatformApiResponse response = router.route(request("GET", List.of("config"), Map.of()));

    verify(configPort).export(EnumSet.of(ConfigSection.CURRENT));
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"CURRENT\":{\"enabled\":\"true\",\"node\":{\"name\":\"alpha\"}}}", response.body());
  }

  private static PlatformApiRequest request(
      String method, List<String> pathSegments, Map<String, List<String>> queryParameters) {
    return new PlatformApiRequest(method, pathSegments, queryParameters);
  }
}
