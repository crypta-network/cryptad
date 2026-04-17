package network.crypta.platform.api;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
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
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueDownloadRequest;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueuePageRequest;
import network.crypta.runtime.spi.QueuePageSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.runtime.spi.UnknownPeerException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PlatformApiRouterTest {
  private static final Instant STARTED_AT = Instant.parse("2024-01-02T03:04:05Z");
  private static final String APP_ID = "alpha";
  private static final String INSTALL_ROUTE_APP_ID = "install";
  private static final String APP_NAME = "Alpha App";
  private static final String APP_VERSION = "2.1.0";
  private static final String APP_UI_ENTRY = "ui/index.html";
  private static final long APP_PID = 4242L;

  @Mock private RuntimePorts runtimePorts;
  @Mock private NodeInfoPort nodeInfoPort;
  @Mock private PeerPort peerPort;
  @Mock private ConfigPort configPort;
  @Mock private ConnectivityPort connectivityPort;
  @Mock private SecurityLevelsPort securityLevelsPort;
  @Mock private QueuePagePort queuePagePort;
  @Mock private QueueMutationPort queueMutationPort;
  @Mock private QueueDownloadPort queueDownloadPort;
  @Mock private QueueSupportPort queueSupportPort;
  @Mock private QueueCompletionPort queueCompletionPort;
  @Mock private AppHost appHost;

  @TempDir private Path tempDir;

  private PlatformApiRouter router;

  @BeforeEach
  void setUp() {
    when(runtimePorts.nodeInfo()).thenReturn(nodeInfoPort);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(runtimePorts.config()).thenReturn(configPort);
    when(runtimePorts.connectivity()).thenReturn(connectivityPort);
    when(runtimePorts.securityLevels()).thenReturn(securityLevelsPort);
    when(runtimePorts.queuePage()).thenReturn(queuePagePort);
    when(runtimePorts.queueMutation()).thenReturn(queueMutationPort);
    when(runtimePorts.queueDownload()).thenReturn(queueDownloadPort);
    when(runtimePorts.queueSupport()).thenReturn(queueSupportPort);
    when(runtimePorts.queueCompletion()).thenReturn(queueCompletionPort);
    router = new PlatformApiRouter(runtimePorts, appHost);
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

  @Test
  void route_whenQueueSnapshotRequested_expectDetachedQueueJson() throws Exception {
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queuePagePort.renderPage(new QueuePageRequest(false, true, "priority", true)))
        .thenReturn(
            new QueuePageSnapshot(
                "Downloads",
                "<div>before<!--CRYPTA_ALERT_SUMMARY--><!--CRYPTA_QUEUE_FORM_PASSWORD-->"
                    + "after</div>"));

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("queue"),
                Map.of(
                    "page", List.of("downloads"),
                    "advancedMode", List.of("true"),
                    "sortBy", List.of("priority"),
                    "reversed", List.of("true"))));

    verify(queueCompletionPort).ensureTrackingStarted(false);
    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            orderedJson(
                Map.entry("page", "downloads"),
                Map.entry("pageTitle", "Downloads"),
                Map.entry("contentHtml", "<div>beforeafter</div>"),
                Map.entry("advancedMode", true),
                Map.entry("sortBy", "priority"),
                Map.entry("reversed", true))),
        response.body());
  }

  @Test
  void route_whenQueuePageMissing_expectBadRequestJson() {
    PlatformApiResponse response = router.route(request("GET", List.of("queue"), Map.of()));

    assertEquals(400, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_query_parameter\",\"message\":\"Missing required query"
            + " parameter 'page'.\"}}",
        response.body());
    verify(queueSupportPort, never()).isQueueBackendEnabled();
  }

  @Test
  void route_whenQueueKeysRequested_expectJsonArrayExport() throws Exception {
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queuePagePort.renderKeyList(true)).thenReturn("USK@alpha\nUSK@beta\n");

    PlatformApiResponse response =
        router.route(request("GET", List.of("queue", "keys"), Map.of("page", List.of("uploads"))));

    verify(queueCompletionPort).ensureTrackingStarted(true);
    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            orderedJson(
                Map.entry("page", "uploads"),
                Map.entry("keyCount", 2),
                Map.entry("keys", List.of("USK@alpha", "USK@beta")))),
        response.body());
  }

  @Test
  void route_whenQueueCountRequested_expectDetachedCountJson() throws Exception {
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queuePagePort.renderCountPage(false))
        .thenReturn(
            new QueuePageSnapshot(
                "Downloads Count", "<div>count<!--CRYPTA_QUEUE_FORM_PASSWORD--></div>"));

    PlatformApiResponse response =
        router.route(
            request("GET", List.of("queue", "count"), Map.of("page", List.of("downloads"))));

    verify(queueCompletionPort).ensureTrackingStarted(false);
    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            orderedJson(
                Map.entry("page", "downloads"),
                Map.entry("pageTitle", "Downloads Count"),
                Map.entry("contentHtml", "<div>count</div>"))),
        response.body());
  }

  @Test
  void route_whenQueueRemoveRequested_expectMutationJsonAndIdentifiersPassedThrough()
      throws Exception {
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("queue", "requests", "remove"),
                orderedStringParameters(
                    Map.entry("identifier-0", List.of("download-1")),
                    Map.entry("identifier-1", List.of("download-2")))));

    verify(queueMutationPort).removeRequests(List.of("download-1", "download-2"));
    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            orderedJson(Map.entry("operation", "remove"), Map.entry("identifierCount", 2))),
        response.body());
  }

  @Test
  void route_whenQueueCleanupDownloadsRequested_expectCleanupJson() throws Exception {
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);

    PlatformApiResponse response =
        router.route(request("POST", List.of("queue", "cleanup", "downloads"), Map.of()));

    verify(queueMutationPort).removeFinishedDownloads();
    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            orderedJson(Map.entry("operation", "cleanup"), Map.entry("target", "downloads"))),
        response.body());
  }

  @Test
  void route_whenQueueDirectDownloadRequested_expectCreatedJsonAndDirectRequest() throws Exception {
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("queue", "downloads"),
                Map.of(
                    "fetchUri", List.of("KSK@queued"),
                    "filterData", List.of("true"),
                    "expectedMimeType", List.of("text/plain"))));

    verify(queueDownloadPort)
        .enqueueDownload(
            new QueueDownloadRequest("KSK@queued", true, "text/plain", "forever", "direct", null));
    assertEquals(201, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            orderedJson(
                Map.entry("operation", "create_direct_download"),
                Map.entry("fetchUri", "KSK@queued"),
                Map.entry("filterData", true),
                Map.entry("expectedMimeType", "text/plain"),
                Map.entry("returnType", "direct"))),
        response.body());
  }

  @Test
  void route_whenAppsListRequested_expectAppsEnvelopeAndMergedRunningState() throws Exception {
    InstalledAppSnapshot installed = installedSnapshot();
    RunningAppSnapshot running = runningSnapshot();
    when(appHost.listInstalled()).thenReturn(List.of(installed));
    when(appHost.listRunning()).thenReturn(List.of(running));

    PlatformApiResponse response = router.route(request("GET", List.of("apps"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            Map.of("apps", List.of(summary(true, true, APP_PID, STARTED_AT)))),
        response.body());
  }

  @Test
  void route_whenAppsDescribeRequested_expectAppEnvelopeAndMergedRunningState() throws Exception {
    InstalledAppSnapshot installed = installedSnapshot();
    RunningAppSnapshot running = runningSnapshot();
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.of(running));

    PlatformApiResponse response = router.route(request("GET", List.of("apps", APP_ID), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(Map.of("app", summary(true, true, APP_PID, STARTED_AT))),
        response.body());
  }

  @Test
  void route_whenAppIdMatchesInstallRoute_expectDescribeJson() throws Exception {
    InstalledAppSnapshot installed = installedSnapshot(INSTALL_ROUTE_APP_ID);
    when(appHost.describe(INSTALL_ROUTE_APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(INSTALL_ROUTE_APP_ID)).thenReturn(Optional.empty());

    PlatformApiResponse response =
        router.route(request("GET", List.of("apps", INSTALL_ROUTE_APP_ID), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(Map.of("app", installRouteSummary(true))), response.body());
  }

  @Test
  void route_whenAppIdMatchesInstallRouteAndDeleteRequested_expectUninstallJson() throws Exception {
    InstalledAppSnapshot installed = installedSnapshot(INSTALL_ROUTE_APP_ID);
    when(appHost.describe(INSTALL_ROUTE_APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(INSTALL_ROUTE_APP_ID)).thenReturn(Optional.empty());

    PlatformApiResponse response =
        router.route(request("DELETE", List.of("apps", INSTALL_ROUTE_APP_ID), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(Map.of("app", installRouteSummary(false))), response.body());
  }

  @Test
  void route_whenInstallOptionsRequested_expectMethodNotAllowedWithAllowPost() {
    PlatformApiResponse response =
        router.route(request("OPTIONS", List.of("apps", "install"), Map.of()));

    assertEquals(405, response.statusCode());
    assertEquals("Method Not Allowed", response.reasonPhrase());
    assertEquals(Map.of("Allow", "POST"), response.headers());
    assertEquals(
        "{\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Platform API v1 supports POST"
            + " requests only.\"}}",
        response.body());
  }

  @Test
  void route_whenInstallHeadRequested_expectMethodNotAllowedWithAllowPost() {
    PlatformApiResponse response =
        router.route(request("HEAD", List.of("apps", "install"), Map.of()));

    assertEquals(405, response.statusCode());
    assertEquals("Method Not Allowed", response.reasonPhrase());
    assertEquals(Map.of("Allow", "POST"), response.headers());
    assertEquals(
        "{\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Platform API v1 supports POST"
            + " requests only.\"}}",
        response.body());
  }

  @Test
  void route_whenAppMissing_expectJson404() throws Exception {
    when(appHost.describe("missing")).thenReturn(Optional.empty());

    PlatformApiResponse response =
        router.route(request("GET", List.of("apps", "missing"), Map.of()));

    assertEquals(404, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"app_not_found\",\"message\":\"App not found.\"}}", response.body());
  }

  @Test
  void route_whenAppStartRequested_expectRunningSummaryWithoutToken() throws Exception {
    InstalledAppSnapshot installed = installedSnapshot();
    InstalledAppSnapshot launched = installedSnapshot(APP_ID, "Alpha App 2", "2.2.0", "ui/v2.html");
    RunningAppSnapshot running = runningSnapshot(launched);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.start(APP_ID)).thenReturn(running);

    PlatformApiResponse response =
        router.route(request("POST", List.of("apps", APP_ID, "start"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            Map.of(
                "app",
                summaryFor(
                    APP_ID,
                    "Alpha App 2",
                    "2.2.0",
                    "ui/v2.html",
                    true,
                    true,
                    APP_PID,
                    STARTED_AT))),
        response.body());
  }

  @Test
  void route_whenAppInstallRequested_expectCreatedJsonAndNoLaunchToken() throws Exception {
    Path stagedDir = stageApp();
    InstalledAppSnapshot installed = installedSnapshot();
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.installFromDirectory(stagedDir)).thenReturn(installed);

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(201, response.statusCode());
    assertEquals("Created", response.reasonPhrase());
    assertEquals(
        PlatformApiJsonWriter.write(Map.of("app", summary(true, false, null, null))),
        response.body());
  }

  @Test
  void route_whenInstalledManifestUnreadableAndUpdateRequested_expectUpdatedSummaryJson()
      throws Exception {
    Path stagedDir = stageApp("9.9.9", APP_ID, APP_NAME);
    InstalledAppSnapshot updated = installedSnapshot(APP_ID, APP_NAME, "9.9.9", APP_UI_ENTRY);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.updateFromDirectory(APP_ID, stagedDir)).thenReturn(updated);

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("apps", APP_ID, "update"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            Map.of(
                "app",
                summaryFor(APP_ID, APP_NAME, "9.9.9", APP_UI_ENTRY, true, false, null, null))),
        response.body());
    verify(appHost, never()).describe(APP_ID);
  }

  @Test
  void route_whenAppUpdateTargetMissing_expectNotFoundJson() throws Exception {
    Path stagedDir = stageApp("9.9.9", APP_ID, APP_NAME);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.updateFromDirectory(APP_ID, stagedDir))
        .thenThrow(new AppHostException("app is not installed: alpha"));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("apps", APP_ID, "update"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(404, response.statusCode());
    assertEquals("Not Found", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"app_not_found\",\"message\":\"App not found.\"}}", response.body());
    verify(appHost, never()).describe(APP_ID);
    verify(appHost).updateFromDirectory(APP_ID, stagedDir);
  }

  @Test
  void route_whenAppUpdateRequestedWhileRunning_expectConflictJson() throws Exception {
    Path stagedDir = stageApp("9.9.9", APP_ID, APP_NAME);
    when(appHost.status(APP_ID)).thenReturn(Optional.of(runningSnapshot()));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("apps", APP_ID, "update"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(409, response.statusCode());
    assertEquals("Conflict", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"app_conflict\",\"message\":\"cannot update a running app:"
            + " alpha\"}}",
        response.body());
    verify(appHost, never()).describe(APP_ID);
    verify(appHost, never()).updateFromDirectory(APP_ID, stagedDir);
  }

  @Test
  void route_whenAppUpdateStagedBundleTargetsDifferentApp_expectBadRequestJson() throws Exception {
    Path stagedDir = stageApp("9.9.9", "beta", "Beta App");
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("apps", APP_ID, "update"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(400, response.statusCode());
    assertEquals("Bad Request", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_bundle\",\"message\":\"staged app bundle app.id"
            + " does not match target app: beta\"}}",
        response.body());
    verify(appHost, never()).describe(APP_ID);
    verify(appHost, never()).updateFromDirectory(APP_ID, stagedDir);
  }

  @Test
  void route_whenInstalledManifestUnreadableAndUpdateBundleInvalid_expectBadRequestJson()
      throws Exception {
    Path stagedDir = stageApp("9.9.9", APP_ID, APP_NAME);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.updateFromDirectory(APP_ID, stagedDir))
        .thenThrow(
            new AppHostException(
                "app.exec does not resolve to a file in copied bundle: bin/launch"));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("apps", APP_ID, "update"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(400, response.statusCode());
    assertEquals("Bad Request", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_bundle\",\"message\":\"app.exec does not resolve"
            + " to a file in copied bundle: bin/launch\"}}",
        response.body());
    verify(appHost, never()).describe(APP_ID);
    verify(appHost).updateFromDirectory(APP_ID, stagedDir);
  }

  @Test
  void route_whenAppUpdateMissingStagedDir_expectBadRequestJson() {
    PlatformApiResponse response =
        router.route(request("POST", List.of("apps", APP_ID, "update"), Map.of()));

    assertEquals(400, response.statusCode());
    assertEquals("Bad Request", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_query_parameter\",\"message\":\"Missing required query"
            + " parameter 'stagedDir'.\"}}",
        response.body());
    verifyNoInteractions(appHost);
  }

  @Test
  void route_whenAppInstallMissingStagedDir_expectBadRequestJson() {
    PlatformApiResponse response =
        router.route(request("POST", List.of("apps", "install"), Map.of()));

    assertEquals(400, response.statusCode());
    assertEquals("Bad Request", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_query_parameter\",\"message\":\"Missing required query"
            + " parameter 'stagedDir'.\"}}",
        response.body());
    verifyNoInteractions(appHost);
  }

  @Test
  void route_whenAppInstallStagedDirBlank_expectBadRequestJson() {
    PlatformApiResponse response =
        router.route(
            request("POST", List.of("apps", "install"), Map.of("stagedDir", List.of("   "))));

    assertEquals(400, response.statusCode());
    assertEquals("Bad Request", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_query_parameter\",\"message\":\"Missing required query"
            + " parameter 'stagedDir'.\"}}",
        response.body());
    verifyNoInteractions(appHost);
  }

  @Test
  void route_whenAppInstallValidationFails_expectBadRequestJson() throws Exception {
    Path stagedDir = stageApp();
    when(appHost.describe(APP_ID)).thenAnswer(_ -> Optional.empty());
    when(appHost.installFromDirectory(stagedDir))
        .thenThrow(new AppHostException("staging directory must not contain symlinks: bad-link"));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(400, response.statusCode());
    assertEquals("Bad Request", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_bundle\",\"message\":\"staging directory must not"
            + " contain symlinks: bad-link\"}}",
        response.body());
  }

  @Test
  void route_whenAppInstallManagedLayoutFails_expectInternalErrorJson() throws Exception {
    Path stagedDir = stageApp();
    when(appHost.describe(APP_ID)).thenAnswer(_ -> Optional.empty());
    when(appHost.installFromDirectory(stagedDir))
        .thenThrow(
            new AppHostException(
                "installedAppsDir must not be a symlink, reparse point, or alias:"
                    + " /srv/node/apps/installed"));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(500, response.statusCode());
    assertEquals("Internal Server Error", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"internal_error\",\"message\":\"Failed to install app.\"}}",
        response.body());
  }

  @Test
  void route_whenAppStartRepeated_expectConflictJson() {
    when(appHost.status(APP_ID)).thenReturn(Optional.of(runningSnapshot()));

    PlatformApiResponse response =
        router.route(request("POST", List.of("apps", APP_ID, "start"), Map.of()));

    assertEquals(409, response.statusCode());
    assertEquals("Conflict", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"app_conflict\",\"message\":\"app is already running: alpha\"}}",
        response.body());
  }

  @Test
  void route_whenAppAlreadyRunningAndManifestUnreadable_expectConflictJson() throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.of(runningSnapshot()));

    PlatformApiResponse response =
        router.route(request("POST", List.of("apps", APP_ID, "start"), Map.of()));

    assertEquals(409, response.statusCode());
    assertEquals("Conflict", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"app_conflict\",\"message\":\"app is already running: alpha\"}}",
        response.body());
    verify(appHost).status(APP_ID);
    verify(appHost, never()).describe(APP_ID);
    verify(appHost, never()).start(APP_ID);
  }

  @Test
  void route_whenAppStartRacesToRunning_expectConflictJson() throws Exception {
    InstalledAppSnapshot installed = installedSnapshot();
    when(appHost.describe(APP_ID)).thenAnswer(_ -> Optional.of(installed));
    when(appHost.status(APP_ID)).thenAnswer(new TwoStepOptionalAnswer<>(null, runningSnapshot()));
    when(appHost.start(APP_ID)).thenThrow(new AppHostException("app is already running: alpha"));

    PlatformApiResponse response =
        router.route(request("POST", List.of("apps", APP_ID, "start"), Map.of()));

    assertEquals(409, response.statusCode());
    assertEquals("Conflict", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"app_conflict\",\"message\":\"app is already running: alpha\"}}",
        response.body());
  }

  @Test
  void route_whenAppStartRaceFindsRunningAfterManifestBecomesUnreadable_expectConflictJson()
      throws Exception {
    InstalledAppSnapshot installed = installedSnapshot();
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed))
        .thenThrow(new IOException("corrupt manifest"));
    when(appHost.status(APP_ID)).thenAnswer(new TwoStepOptionalAnswer<>(null, runningSnapshot()));
    when(appHost.start(APP_ID)).thenThrow(new AppHostException("app is already running: alpha"));

    PlatformApiResponse response =
        router.route(request("POST", List.of("apps", APP_ID, "start"), Map.of()));

    assertEquals(409, response.statusCode());
    assertEquals("Conflict", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"app_conflict\",\"message\":\"app is already running: alpha\"}}",
        response.body());
  }

  @Test
  void route_whenAppStopRequested_expectStoppedSummaryJson() throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.of(runningSnapshot()));
    when(appHost.stop(APP_ID)).thenReturn(true);

    PlatformApiResponse response =
        router.route(request("POST", List.of("apps", APP_ID, "stop"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(Map.of("app", summary(true, false, null, null))),
        response.body());
  }

  @Test
  void route_whenRunningAppManifestUnreadableDuringStop_expectStoppedSummaryJson()
      throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.of(runningSnapshot()));
    when(appHost.stop(APP_ID)).thenReturn(true);

    PlatformApiResponse response =
        router.route(request("POST", List.of("apps", APP_ID, "stop"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals("OK", response.reasonPhrase());
    assertEquals(
        PlatformApiJsonWriter.write(Map.of("app", summary(true, false, null, null))),
        response.body());
  }

  @Test
  void route_whenAppUninstallRequested_expectInstalledFalseSummaryJson() throws Exception {
    InstalledAppSnapshot installed = installedSnapshot();
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    PlatformApiResponse response =
        router.route(request("DELETE", List.of("apps", APP_ID), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(Map.of("app", summary(false, false, null, null))),
        response.body());
  }

  @Test
  void route_whenAppManifestUnreadableDuringUninstall_expectCleanupSummaryJson() throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenThrow(new IOException("corrupt manifest"));

    PlatformApiResponse response =
        router.route(request("DELETE", List.of("apps", APP_ID), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals("OK", response.reasonPhrase());
    assertEquals(PlatformApiJsonWriter.write(Map.of("app", unknownSummary())), response.body());
  }

  @Test
  void route_whenAppUninstallRacesToMissing_expectNotFoundJson() throws Exception {
    InstalledAppSnapshot installed = installedSnapshot();
    when(appHost.describe(APP_ID)).thenAnswer(new TwoStepOptionalAnswer<>(installed, null));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    doThrow(new AppHostException("app is not installed: alpha")).when(appHost).uninstall(APP_ID);

    PlatformApiResponse response =
        router.route(request("DELETE", List.of("apps", APP_ID), Map.of()));

    assertEquals(404, response.statusCode());
    assertEquals("Not Found", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"app_not_found\",\"message\":\"App not found.\"}}", response.body());
  }

  @Test
  void route_whenAppUninstallRaceFindsRunningAfterManifestBecomesUnreadable_expectConflictJson()
      throws Exception {
    InstalledAppSnapshot installed = installedSnapshot();
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed))
        .thenThrow(new IOException("corrupt manifest"));
    when(appHost.status(APP_ID)).thenAnswer(new TwoStepOptionalAnswer<>(null, runningSnapshot()));
    doThrow(new AppHostException("cannot uninstall a running app: alpha"))
        .when(appHost)
        .uninstall(APP_ID);

    PlatformApiResponse response =
        router.route(request("DELETE", List.of("apps", APP_ID), Map.of()));

    assertEquals(409, response.statusCode());
    assertEquals("Conflict", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"app_conflict\",\"message\":\"cannot uninstall a running app:"
            + " alpha\"}}",
        response.body());
  }

  @Test
  void route_whenAppInstallRepeated_expectConflictJson() throws Exception {
    Path stagedDir = stageApp();
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(409, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"app_conflict\",\"message\":\"app already installed: alpha\"}}",
        response.body());
  }

  @Test
  void route_whenInstallRacesToDifferentAlreadyInstalledApp_expectConflictJson() throws Exception {
    Path stagedDir = stageApp();
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.installFromDirectory(stagedDir))
        .thenThrow(new AppHostException("app already installed: beta"));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(409, response.statusCode());
    assertEquals("Conflict", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"app_conflict\",\"message\":\"app already installed: beta\"}}",
        response.body());
  }

  private static PlatformApiRequest request(
      String method, List<String> pathSegments, Map<String, List<String>> queryParameters) {
    return new PlatformApiRequest(method, pathSegments, queryParameters);
  }

  @SafeVarargs
  private static Map<String, Object> orderedJson(Map.Entry<String, Object>... entries) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(entries.length);
    for (Map.Entry<String, Object> entry : entries) {
      json.put(entry.getKey(), entry.getValue());
    }
    return json;
  }

  @SafeVarargs
  private static Map<String, List<String>> orderedStringParameters(
      Map.Entry<String, List<String>>... entries) {
    LinkedHashMap<String, List<String>> parameters = LinkedHashMap.newLinkedHashMap(entries.length);
    for (Map.Entry<String, List<String>> entry : entries) {
      parameters.put(entry.getKey(), entry.getValue());
    }
    return parameters;
  }

  private InstalledAppSnapshot installedSnapshot() {
    return installedSnapshot(APP_ID);
  }

  private InstalledAppSnapshot installedSnapshot(String appId) {
    return installedSnapshot(appId, APP_NAME, APP_VERSION, APP_UI_ENTRY);
  }

  private InstalledAppSnapshot installedSnapshot(
      String appId, String appName, String appVersion, String appUiEntry) {
    AppManifest manifest =
        new AppManifest(
            1,
            appId,
            appName,
            appVersion,
            "bin/launch",
            appUiEntry,
            List.of("network.access", "file.read"),
            4096L,
            8192L);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            appId,
            tempDir.resolve("installed").resolve(appId),
            tempDir.resolve("data").resolve(appId),
            tempDir.resolve("cache").resolve(appId),
            tempDir.resolve("run").resolve(appId));
    return new InstalledAppSnapshot(manifest, paths);
  }

  private RunningAppSnapshot runningSnapshot() {
    InstalledAppSnapshot installed = installedSnapshot();
    return runningSnapshot(installed);
  }

  private RunningAppSnapshot runningSnapshot(InstalledAppSnapshot installed) {
    return new RunningAppSnapshot(
        installed.manifest(),
        installed.paths(),
        "token-" + installed.manifest().appId(),
        APP_PID,
        STARTED_AT);
  }

  private Path stageApp() throws Exception {
    return stageApp(APP_VERSION, APP_ID, APP_NAME);
  }

  private Path stageApp(String appVersion, String appId, String appName) throws Exception {
    Path stagedDir = Files.createTempDirectory(tempDir, "staged-");
    Files.writeString(
        stagedDir.resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch
        app.ui.entry=%s
        app.permissions=network.access,file.read
        quota.data.bytes=4096
        quota.cache.bytes=8192
        """
            .formatted(appId, appName, appVersion, APP_UI_ENTRY));
    return stagedDir;
  }

  private static Map<String, Object> summary(
      boolean installed, boolean running, Long pid, Instant startedAt) {
    return summaryFor(
        APP_ID, APP_NAME, APP_VERSION, APP_UI_ENTRY, installed, running, pid, startedAt);
  }

  private static Map<String, Object> installRouteSummary(boolean installed) {
    return summaryFor(
        INSTALL_ROUTE_APP_ID, APP_NAME, APP_VERSION, APP_UI_ENTRY, installed, false, null, null);
  }

  private static Map<String, Object> summaryFor(
      String appId,
      String appName,
      String appVersion,
      String appUiEntry,
      boolean installed,
      boolean running,
      Long pid,
      Instant startedAt) {
    LinkedHashMap<String, Object> summary = LinkedHashMap.newLinkedHashMap(10);
    summary.put("appId", appId);
    summary.put("name", appName);
    summary.put("version", appVersion);
    summary.put("uiEntry", appUiEntry);
    summary.put("permissions", List.of("network.access", "file.read"));
    LinkedHashMap<String, Object> quota = LinkedHashMap.newLinkedHashMap(2);
    quota.put("dataBytes", 4096L);
    quota.put("cacheBytes", 8192L);
    summary.put("quota", quota);
    summary.put("installed", installed);
    summary.put("running", running);
    summary.put("pid", pid);
    summary.put("startedAt", startedAt == null ? null : startedAt.toString());
    return summary;
  }

  private static Map<String, Object> unknownSummary() {
    LinkedHashMap<String, Object> summary = LinkedHashMap.newLinkedHashMap(10);
    summary.put("appId", APP_ID);
    summary.put("name", null);
    summary.put("version", null);
    summary.put("uiEntry", null);
    summary.put("permissions", List.of());
    LinkedHashMap<String, Object> quota = LinkedHashMap.newLinkedHashMap(2);
    quota.put("dataBytes", null);
    quota.put("cacheBytes", null);
    summary.put("quota", quota);
    summary.put("installed", false);
    summary.put("running", false);
    summary.put("pid", null);
    summary.put("startedAt", null);
    return summary;
  }

  private static final class TwoStepOptionalAnswer<T>
      implements org.mockito.stubbing.Answer<Optional<T>> {
    private T current;
    private final T next;

    private TwoStepOptionalAnswer(T current, T next) {
      this.current = current;
      this.next = next;
    }

    @Override
    public Optional<T> answer(org.mockito.invocation.InvocationOnMock invocation) {
      T result = current;
      current = next;
      return Optional.ofNullable(result);
    }
  }
}
