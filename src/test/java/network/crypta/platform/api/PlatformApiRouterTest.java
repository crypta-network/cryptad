package network.crypta.platform.api;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appdata.AppDataStoreConfig;
import network.crypta.platform.api.appdata.InMemoryAppDataStore;
import network.crypta.platform.api.appupdates.AppDataMigrationRunner;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.appcatalog.AppCatalogChangelog;
import network.crypta.platform.appcatalog.AppCatalogCompatibilityMetadata;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogFetchStatus;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogReviewMetadata;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostConfigurationException;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppProcessLogSnapshot;
import network.crypta.platform.apphost.AppQuotaPolicy;
import network.crypta.platform.apphost.AppQuotaStatus;
import network.crypta.platform.apphost.AppQuotaUsage;
import network.crypta.platform.apphost.AppRollbackRecord;
import network.crypta.platform.apphost.AppRuntimeState;
import network.crypta.platform.apphost.AppRuntimeStatusSnapshot;
import network.crypta.platform.apphost.AppUninstallOptions;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.sandbox.AppSandboxPolicy;
import network.crypta.platform.apphost.sandbox.AppSandboxProviders;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.runtime.spi.AlertFeedPort;
import network.crypta.runtime.spi.AlertListSnapshot;
import network.crypta.runtime.spi.AlertMutationPort;
import network.crypta.runtime.spi.AlertSeverity;
import network.crypta.runtime.spi.AlertSnapshot;
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
import network.crypta.runtime.spi.CoreUpdateActionPort;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetPeerSettingsUpdate;
import network.crypta.runtime.spi.DiagnosticPort;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.runtime.spi.FirstTimeWizardCurrentBandwidthLimits;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.runtime.spi.FirstTimeWizardSubmission;
import network.crypta.runtime.spi.LegacyAdminSurfaceUsage;
import network.crypta.runtime.spi.LegacyAdminUsageSnapshot;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeGreetingSnapshot;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.runtime.spi.PeerAddRejectedException;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.PeerTrust;
import network.crypta.runtime.spi.PeerVisibility;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueDownloadRequest;
import network.crypta.runtime.spi.QueueInsertOptions;
import network.crypta.runtime.spi.QueueInsertOutcome;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueLocalDirectoryInsertRequest;
import network.crypta.runtime.spi.QueueLocalFileInsertRequest;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueuePageRequest;
import network.crypta.runtime.spi.QueuePageSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.RemovedPeerSnapshot;
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
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PlatformApiRouterTest {
  private static final String CANONICAL_UPDATE_URI =
      "uQnFwn0aEFSAZihnSDduEHUd3GUmGg68ATn5R95MKJo,"
          + "mcNiZqosfZ1F~PkZY8v1TuDKsY6noda-hGRXvu7uUFc,AQACAAE";
  private static final String FULL_UPDATE_URI = "USK@" + CANONICAL_UPDATE_URI + "/info/1234";

  private static final Instant STARTED_AT = Instant.parse("2024-01-02T03:04:05Z");
  private static final String APP_ID = "alpha";
  private static final String INSTALL_ROUTE_APP_ID = "install";
  private static final String APP_NAME = "Alpha App";
  private static final String APP_VERSION = "2.1.0";
  private static final String APP_UI_ENTRY = "ui/index.html";
  private static final long APP_PID = 4242L;
  private static final long MANIFEST_DATA_QUOTA_BYTES = 4096L;
  private static final long MANIFEST_CACHE_QUOTA_BYTES = 8192L;
  private static final String FIRST_PARTY_TRUSTED_KEY_ID = "first-party-catalog";
  private static final String CATALOG_MINIMUM_CRYPTA_VERSION = "1400";

  @Mock private RuntimePorts runtimePorts;
  @Mock private NodeInfoPort nodeInfoPort;
  @Mock private PeerPort peerPort;
  @Mock private DarknetConnectionsPort darknetConnectionsPort;
  @Mock private ConfigPort configPort;
  @Mock private ConnectivityPort connectivityPort;
  @Mock private SecurityLevelsPort securityLevelsPort;
  @Mock private CoreUpdateActionPort coreUpdateActionPort;
  @Mock private FirstTimeWizardPort firstTimeWizardPort;
  @Mock private DiagnosticPort diagnosticPort;
  @Mock private QueuePagePort queuePagePort;
  @Mock private QueueMutationPort queueMutationPort;
  @Mock private QueueDownloadPort queueDownloadPort;
  @Mock private QueueInsertPort queueInsertPort;
  @Mock private QueueSupportPort queueSupportPort;
  @Mock private QueueCompletionPort queueCompletionPort;
  @Mock private AlertFeedPort alertFeedPort;
  @Mock private AlertMutationPort alertMutationPort;
  @Mock private AppHost appHost;

  @TempDir private Path tempDir;

  private PlatformApiRouter router;

  @BeforeEach
  void setUp() throws IOException {
    when(runtimePorts.nodeInfo()).thenReturn(nodeInfoPort);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(runtimePorts.darknetConnections()).thenReturn(darknetConnectionsPort);
    when(runtimePorts.config()).thenReturn(configPort);
    when(runtimePorts.connectivity()).thenReturn(connectivityPort);
    when(runtimePorts.securityLevels()).thenReturn(securityLevelsPort);
    when(runtimePorts.coreUpdateAction()).thenReturn(coreUpdateActionPort);
    when(runtimePorts.firstTimeWizard()).thenReturn(firstTimeWizardPort);
    when(runtimePorts.diagnostic()).thenReturn(diagnosticPort);
    when(runtimePorts.queuePage()).thenReturn(queuePagePort);
    when(runtimePorts.queueMutation()).thenReturn(queueMutationPort);
    when(runtimePorts.queueDownload()).thenReturn(queueDownloadPort);
    when(runtimePorts.queueInsert()).thenReturn(queueInsertPort);
    when(runtimePorts.queueSupport()).thenReturn(queueSupportPort);
    when(runtimePorts.queueCompletion()).thenReturn(queueCompletionPort);
    when(runtimePorts.alertFeed()).thenReturn(alertFeedPort);
    when(runtimePorts.alertMutation()).thenReturn(alertMutationPort);
    lenient()
        .when(appHost.runtimeStatus(any()))
        .thenAnswer(invocation -> stoppedRuntimeStatus(invocation.getArgument(0)));
    lenient()
        .when(appHost.inactiveSandboxStatus(any()))
        .thenAnswer(invocation -> AppSandboxProviders.inactiveStatus(invocation.getArgument(0)));
    router = new PlatformApiRouter(runtimePorts, appHost);
  }

  private PlatformApiRouter routerWithVault() throws IOException {
    return routerWithVault(null);
  }

  private PlatformApiRouter routerWithVault(AppCatalogManager appCatalogManager)
      throws IOException {
    return new PlatformApiRouter(
        runtimePorts,
        appHost,
        appCatalogManager,
        null,
        AppUiOriginRegistry.sameOriginOnly(),
        AppVaultService.open(tempDir.resolve("router-vault")));
  }

  private void stubQueueInsertCompatibilityModes() {
    when(queueSupportPort.supportedInsertCompatibilityModes())
        .thenReturn(
            List.of(
                "COMPAT_1468",
                "COMPAT_1250_EXACT",
                "COMPAT_1250",
                "COMPAT_1251",
                "COMPAT_1255",
                "COMPAT_1416"));
    when(queueSupportPort.defaultInsertCompatibilityMode()).thenReturn("COMPAT_1468");
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
  void route_whenAlertsRequested_expectStructuredAlertSnapshotJson() {
    AlertListSnapshot snapshot = org.mockito.Mockito.mock(AlertListSnapshot.class);
    AlertSnapshot alert = org.mockito.Mockito.mock(AlertSnapshot.class);
    when(alert.id()).thenReturn(42);
    when(alert.title()).thenReturn("Update available");
    when(alert.shortText()).thenReturn("Updater");
    when(alert.text()).thenReturn("A new core package is ready.");
    when(alert.severity()).thenReturn(AlertSeverity.WARNING);
    when(alert.dismissible()).thenReturn(true);
    when(alert.dismissLabel()).thenReturn("Delete");
    when(alert.eventNotification()).thenReturn(false);
    when(alert.updatedTimeMillis()).thenReturn(123L);
    when(snapshot.alerts()).thenReturn(List.of(alert));
    when(alertFeedPort.snapshot()).thenReturn(snapshot);

    PlatformApiResponse response = router.route(request("GET", List.of("alerts"), Map.of()));

    verify(alertFeedPort).snapshot();
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"alertCount\":1,\"dismissibleCount\":1,\"eventNotificationCount\":0,"
            + "\"highestSeverity\":\"WARNING\",\"alerts\":[{\"id\":42,\"title\":\"Update"
            + " available\",\"shortText\":\"Updater\",\"text\":\"A new core package is ready.\","
            + "\"severity\":\"WARNING\",\"dismissible\":true,\"dismissLabel\":\"Delete\","
            + "\"eventNotification\":false,\"updatedTimeMillis\":123}]}",
        response.body());
  }

  @Test
  void route_whenAlertDismissRequested_expectMutationSummary() {
    PlatformApiResponse response =
        router.route(request("POST", List.of("alerts", "-17", "dismiss"), Map.of()));

    verify(alertMutationPort).dismiss(-17);
    assertEquals(200, response.statusCode());
    assertEquals("{\"operation\":\"dismiss\",\"alertId\":-17}", response.body());
  }

  @Test
  void route_whenAlertDismissAlertIdMalformed_expectBadRequestJson() {
    PlatformApiResponse response =
        router.route(request("POST", List.of("alerts", "not-a-number", "dismiss"), Map.of()));

    verifyNoInteractions(alertMutationPort);
    assertEquals(400, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_path_parameter\",\"message\":\"Alert route parameter"
            + " 'alertId' must be a valid integer.\"}}",
        response.body());
  }

  @Test
  void route_whenDiagnosticsRequested_expectStructuredDiagnosticsJson() {
    when(diagnosticPort.snapshot())
        .thenReturn(
            new DiagnosticReportSnapshot(
                List.of(
                    new DiagnosticSectionSnapshot(
                        "System Information:", List.of("alpha", "", "beta")))));

    PlatformApiResponse response = router.route(request("GET", List.of("diagnostics"), Map.of()));

    verify(diagnosticPort).snapshot();
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"sectionCount\":1,\"sections\":[{\"title\":\"System Information:\",\"lines\":[\"alpha\","
            + "\"\",\"beta\"]}],\"plainTextExport\":\"System Information:\\nalpha\\n\\nbeta\\n\"}",
        response.body());
  }

  @Test
  void route_whenPlatformContractRequest_expectContractJson() {
    PlatformApiResponse response =
        router.route(request("GET", List.of("platform", "contract"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            PlatformApiContractJson.envelope(PlatformApiContract.current())),
        response.body());
  }

  @Test
  void route_whenAppPrincipalReadsContractWithCapability_expectContractJson() {
    PlatformApiResponse response =
        router.route(
            appRequest(
                List.of("platform", "contract"), Map.of(), List.of("platform.contract.read")));

    assertEquals(200, response.statusCode());
    assertTrue(
        response
            .body()
            .contains("\"contractVersion\":" + PlatformApiContract.CURRENT_CONTRACT_VERSION));
  }

  @Test
  void route_whenAppPrincipalReadsContractWithoutCapability_expectForbidden() {
    PlatformApiResponse response =
        router.route(appRequest(List.of("platform", "contract"), Map.of(), List.of("node.read")));

    assertEquals(403, response.statusCode());
  }

  @Test
  void route_whenDiagnosticsRouterHasLegacyAdminUsage_expectLegacyAdminUsageJson() {
    PlatformApiRouter diagnosticsRouter =
        new PlatformApiRouter(
            runtimePorts,
            appHost,
            null,
            () ->
                new LegacyAdminUsageSnapshot(
                    List.of(
                        new LegacyAdminSurfaceUsage(
                            "queue-downloads",
                            "Download queue",
                            "/downloads/",
                            "PRIMARY_REPLACED",
                            "/apps/queue-manager/",
                            "REDIRECT_TO_REPLACEMENT",
                            1,
                            "phase-6-pr-8",
                            "none",
                            "CANONICAL_AND_SLASHLESS_ALIAS",
                            0,
                            3L,
                            2L,
                            1L,
                            0L,
                            0L,
                            1_770_000_000_000L))));
    when(diagnosticPort.snapshot()).thenReturn(new DiagnosticReportSnapshot(List.of()));

    PlatformApiResponse response =
        diagnosticsRouter.route(request("GET", List.of("diagnostics"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"sectionCount\":0,\"sections\":[],\"plainTextExport\":\"\",\"legacyAdmin\":{\"surfaces\""
            + ":[{\"id\":\"queue-downloads\",\"title\":\"Download queue\",\"path\":\"/downloads/\","
            + "\"state\":\"PRIMARY_REPLACED\",\"replacementUrl\":\"/apps/queue-manager/\","
            + "\"removalMode\":\"REDIRECT_TO_REPLACEMENT\",\"removalWave\":1,"
            + "\"removedByDefaultSince\":\"phase-6-pr-8\",\"fallbackPolicy\":\"none\","
            + "\"removalScope\":\"CANONICAL_AND_SLASHLESS_ALIAS\",\"scopeExpandedInWave\":0,"
            + "\"count\":3,\"replacementResponseCount\":2,"
            + "\"blockedMutatingRequestCount\":1,\"fallbackRenderCount\":0,"
            + "\"retainedOrPendingRenderCount\":0,\"lastSeenEpochMillis\":1770000000000}]}}",
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
  void route_whenPeerSummaryViewRequested_expectStructuredRosterJson() {
    LinkedHashMap<String, String> directValues = LinkedHashMap.newLinkedHashMap(3);
    directValues.put("identity", "peer-1");
    directValues.put("myName", "Alice");
    directValues.put("opennet", "false");
    LinkedHashMap<String, PeerFieldSet> directSubsets = LinkedHashMap.newLinkedHashMap(2);
    directSubsets.put(
        "metadata",
        new PeerFieldSet(
            Map.of(
                "trustLevel", "HIGH",
                "ourVisibility", "NAME_ONLY",
                "isDisabled", "true",
                "disableRoutingHasBeenSetLocally", "true"),
            Map.of()));
    directSubsets.put("volatile", new PeerFieldSet(Map.of("status", "CONNECTED"), Map.of()));
    when(peerPort.list(true, true))
        .thenReturn(List.of(new PeerSnapshot(new PeerFieldSet(directValues, directSubsets))));
    when(darknetConnectionsPort.listPeers())
        .thenReturn(
            List.of(new DarknetConnectionPeerSnapshot(7, "peer-1", "Alice", "trusted", false)));

    PlatformApiResponse response =
        router.route(request("GET", List.of("peers"), Map.of("view", List.of("summary"))));

    verify(peerPort).list(true, true);
    verify(darknetConnectionsPort).listPeers();
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"identity\":\"peer-1\""));
    assertTrue(response.body().contains("\"displayName\":\"Alice\""));
    assertTrue(response.body().contains("\"family\":\"darknet\""));
    assertTrue(response.body().contains("\"trust\":\"HIGH\""));
    assertTrue(response.body().contains("\"visibility\":\"NAME_ONLY\""));
    assertTrue(response.body().contains("\"disabled\":true"));
    assertTrue(response.body().contains("\"routingEnabled\":false"));
    assertTrue(response.body().contains("\"privateNoteText\":\"trusted\""));
  }

  @Test
  void route_whenPeerSummaryViewStatusIsRoutingDisabled_expectEffectiveRoutingDisabledJson() {
    LinkedHashMap<String, String> directValues = LinkedHashMap.newLinkedHashMap(3);
    directValues.put("identity", "peer-1");
    directValues.put("myName", "Alice");
    directValues.put("opennet", "false");
    LinkedHashMap<String, PeerFieldSet> directSubsets = LinkedHashMap.newLinkedHashMap(2);
    directSubsets.put(
        "metadata",
        new PeerFieldSet(Map.of("trustLevel", "HIGH", "ourVisibility", "YES"), Map.of()));
    directSubsets.put("volatile", new PeerFieldSet(Map.of("status", "ROUTING DISABLED"), Map.of()));
    when(peerPort.list(true, true))
        .thenReturn(List.of(new PeerSnapshot(new PeerFieldSet(directValues, directSubsets))));
    when(darknetConnectionsPort.listPeers())
        .thenReturn(
            List.of(new DarknetConnectionPeerSnapshot(7, "peer-1", "Alice", "trusted", true)));

    PlatformApiResponse response =
        router.route(request("GET", List.of("peers"), Map.of("view", List.of("summary"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"routingEnabled\":false"));
  }

  @Test
  void route_whenPeerNamedSummaryRequested_expectRawPeerLookupStillUsed() throws Exception {
    when(peerPort.get("summary", false, false))
        .thenReturn(new PeerSnapshot(new PeerFieldSet(Map.of("identity", "summary"), Map.of())));

    PlatformApiResponse response =
        router.route(request("GET", List.of("peers", "summary"), Map.of()));

    verify(peerPort).get("summary", false, false);
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"identity\":\"summary\""));
  }

  @Test
  void route_whenPeerNamedRosterRequested_expectRawPeerLookupStillUsed() throws Exception {
    when(peerPort.get("roster", false, false))
        .thenReturn(new PeerSnapshot(new PeerFieldSet(Map.of("identity", "roster"), Map.of())));

    PlatformApiResponse response =
        router.route(request("GET", List.of("peers", "roster"), Map.of()));

    verify(peerPort).get("roster", false, false);
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"identity\":\"roster\""));
  }

  @Test
  void route_whenPeerAddRequested_expectCreatedPeerFromParsedReference()
      throws PeerAddRejectedException {
    when(peerPort.add(any(PeerFieldSet.class), eq(PeerTrust.NORMAL), eq(PeerVisibility.YES)))
        .thenReturn(new PeerSnapshot(new PeerFieldSet(Map.of("identity", "peer-added"), Map.of())));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("peers", "add"),
                Map.of(
                    "referenceText",
                    List.of(
                        """
                        identity=peer-added
                        lastGoodVersion=1
                        myName=Alice
                        physical.udp=127.0.0.1:9481
                        End
                        """),
                    "trust",
                    List.of("NORMAL"),
                    "visibility",
                    List.of("YES"))));

    ArgumentCaptor<PeerFieldSet> referenceCaptor = ArgumentCaptor.forClass(PeerFieldSet.class);
    verify(peerPort).add(referenceCaptor.capture(), eq(PeerTrust.NORMAL), eq(PeerVisibility.YES));
    PeerFieldSet reference = referenceCaptor.getValue();
    assertEquals("peer-added", reference.directValues().get("identity"));
    assertEquals("1", reference.directValues().get("lastGoodVersion"));
    assertEquals("Alice", reference.directValues().get("myName"));
    assertEquals(
        "127.0.0.1:9481", reference.directSubsets().get("physical").directValues().get("udp"));
    assertEquals(201, response.statusCode());
    assertTrue(response.body().contains("\"identity\":\"peer-added\""));
  }

  @Test
  void route_whenPeerAddNoteWriteFails_expectCreatedPeerResponseStillReturned() throws Exception {
    when(peerPort.add(any(PeerFieldSet.class), eq(PeerTrust.NORMAL), eq(PeerVisibility.YES)))
        .thenReturn(new PeerSnapshot(new PeerFieldSet(Map.of("identity", "peer-added"), Map.of())));
    when(darknetConnectionsPort.listPeers())
        .thenReturn(List.of(new DarknetConnectionPeerSnapshot(7, "peer-added", "Alice", "", true)));
    when(peerPort.writePrivateDarknetCommentByIdentity("peer-added", "trusted"))
        .thenThrow(new UnknownPeerException("peer-added"));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("peers", "add"),
                Map.of(
                    "referenceText",
                    List.of(
                        """
                        identity=peer-added
                        lastGoodVersion=1
                        myName=Alice
                        physical.udp=127.0.0.1:9481
                        End
                        """),
                    "privateNoteText",
                    List.of("trusted"))));

    verify(peerPort).writePrivateDarknetCommentByIdentity("peer-added", "trusted");
    assertEquals(201, response.statusCode());
    assertTrue(response.body().contains("\"identity\":\"peer-added\""));
  }

  @Test
  void route_whenPeerAddBlankNoteRequested_expectCreatedPeerWithoutPersistingEmptyNote()
      throws Exception {
    when(peerPort.add(any(PeerFieldSet.class), eq(PeerTrust.NORMAL), eq(PeerVisibility.YES)))
        .thenReturn(new PeerSnapshot(new PeerFieldSet(Map.of("identity", "peer-added"), Map.of())));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("peers", "add"),
                Map.of(
                    "referenceText",
                    List.of(
                        """
                        identity=peer-added
                        lastGoodVersion=1
                        myName=Alice
                        physical.udp=127.0.0.1:9481
                        End
                        """),
                    "privateNoteText",
                    List.of("   "))));

    verify(peerPort, never()).writePrivateDarknetCommentByIdentity(any(), any());
    assertEquals(201, response.statusCode());
    assertTrue(response.body().contains("\"identity\":\"peer-added\""));
  }

  @Test
  void route_whenOpennetPeerAddRequestsDarknetOnlyOptions_expectBadRequestJson() {
    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("peers", "add"),
                Map.of(
                    "referenceText",
                    List.of(
                        """
                        identity=peer-added
                        opennet=true
                        lastGoodVersion=1
                        physical.udp=127.0.0.1:9481
                        End
                        """),
                    "trust",
                    List.of("HIGH"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"invalid_query_parameter\""));
    assertTrue(response.body().contains("Opennet peer references do not support"));
    verifyNoInteractions(peerPort);
  }

  @Test
  void route_whenPeerSettingsRequested_expectExactIdentityMutation() throws Exception {
    when(peerPort.updateDarknetPeerByIdentity(eq("peer-1"), any(DarknetPeerSettingsUpdate.class)))
        .thenReturn(new PeerSnapshot(new PeerFieldSet(Map.of("identity", "peer-1"), Map.of())));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("peers", "peer-1", "settings"),
                Map.of(
                    "disabled",
                    List.of("true"),
                    "routingEnabled",
                    List.of("false"),
                    "trust",
                    List.of("LOW"),
                    "visibility",
                    List.of("NO"))));

    ArgumentCaptor<DarknetPeerSettingsUpdate> updateCaptor =
        ArgumentCaptor.forClass(DarknetPeerSettingsUpdate.class);
    verify(peerPort).updateDarknetPeerByIdentity(eq("peer-1"), updateCaptor.capture());
    DarknetPeerSettingsUpdate update = updateCaptor.getValue();
    assertEquals(Boolean.TRUE, update.disabled());
    assertEquals(Boolean.FALSE, update.routingEnabled());
    assertEquals(PeerTrust.LOW, update.trust());
    assertEquals(PeerVisibility.NO, update.visibility());
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"identity\":\"peer-1\""));
  }

  @Test
  void route_whenPeerNamedAddRequested_expectRawPeerLookupStillUsed() throws Exception {
    when(peerPort.get("add", false, false))
        .thenReturn(new PeerSnapshot(new PeerFieldSet(Map.of("identity", "add"), Map.of())));

    PlatformApiResponse response = router.route(request("GET", List.of("peers", "add"), Map.of()));

    verify(peerPort).get("add", false, false);
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"identity\":\"add\""));
  }

  @Test
  void route_whenPeerNoteRequested_expectExactIdentityNoteWrite() throws Exception {
    when(peerPort.writePrivateDarknetCommentByIdentity("peer-1", "updated note"))
        .thenReturn("updated note");

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("peers", "peer-1", "note"),
                Map.of("noteText", List.of("updated note"))));

    verify(peerPort).writePrivateDarknetCommentByIdentity("peer-1", "updated note");
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"noteText\":\"updated note\""));
  }

  @Test
  void route_whenPeerRemoveRequested_expectExactIdentityRemoval() throws Exception {
    when(peerPort.removeByIdentity("peer-1"))
        .thenReturn(new RemovedPeerSnapshot("peer-1", "peer-1"));

    PlatformApiResponse response =
        router.route(request("POST", List.of("peers", "peer-1", "remove"), Map.of()));

    verify(peerPort).removeByIdentity("peer-1");
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"identity\":\"peer-1\""));
  }

  @Test
  void route_whenProtectedPeerRemoveRequestedWithoutForce_expectConflictJson() {
    when(darknetConnectionsPort.listPeers())
        .thenReturn(
            List.of(new DarknetConnectionPeerSnapshot(7, "peer-1", "Alice", "trusted", false)));

    PlatformApiResponse response =
        router.route(request("POST", List.of("peers", "peer-1", "remove"), Map.of()));

    assertEquals(409, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"force_removal_required\""));
    verifyNoInteractions(peerPort);
  }

  @Test
  void route_whenProtectedPeerRemoveRequestedWithForce_expectExactIdentityRemoval()
      throws Exception {
    when(darknetConnectionsPort.listPeers())
        .thenReturn(
            List.of(new DarknetConnectionPeerSnapshot(7, "peer-1", "Alice", "trusted", false)));
    when(peerPort.removeByIdentity("peer-1"))
        .thenReturn(new RemovedPeerSnapshot("peer-1", "peer-1"));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("peers", "peer-1", "remove"),
                Map.of("forceRemoval", List.of("true"))));

    verify(peerPort).removeByIdentity("peer-1");
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"identity\":\"peer-1\""));
  }

  @Test
  void route_whenPeerSettingsRequestedWithoutChanges_expectBadRequestJson() {
    PlatformApiResponse response =
        router.route(request("POST", List.of("peers", "peer-1", "settings"), Map.of()));

    assertEquals(400, response.statusCode());
    verifyNoInteractions(peerPort);
  }

  @Test
  void route_whenPeerSettingsBooleanInvalid_expectBadRequestJson() {
    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("peers", "peer-1", "settings"),
                Map.of("disabled", List.of("sometimes"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"invalid_query_parameter\""));
    verifyNoInteractions(peerPort);
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
  void route_whenConfigOverridesRequested_expectMutationSummary() {
    when(configPort.export(EnumSet.of(ConfigSection.CURRENT, ConfigSection.DATA_TYPES)))
        .thenReturn(
            verificationConfigSnapshot(
                Map.of("updater.enabled", "true", "updater.autoupdate", "false"),
                Map.of("updater.enabled", "boolean", "updater.autoupdate", "boolean")),
            verificationConfigSnapshot(
                Map.of("updater.enabled", "false", "updater.autoupdate", "true"),
                Map.of("updater.enabled", "boolean", "updater.autoupdate", "boolean")));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("config", "overrides"),
                orderedStringParameters(
                    Map.entry("node.updater.enabled", List.of("false")),
                    Map.entry("node.updater.autoupdate", List.of("true")))));

    verify(configPort)
        .applyOverrides(Map.of("node.updater.enabled", "false", "node.updater.autoupdate", "true"));
    assertEquals(200, response.statusCode());
    assertEquals("{\"operation\":\"apply_overrides\",\"overrideCount\":2}", response.body());
  }

  @Test
  void route_whenConfigOverridesRejected_expectJson400WithoutPersisting() {
    when(configPort.export(EnumSet.of(ConfigSection.CURRENT, ConfigSection.DATA_TYPES)))
        .thenReturn(
            verificationConfigSnapshot(
                Map.of("updater.enabled", "true", "updater.autoupdate", "false"),
                Map.of("updater.enabled", "boolean", "updater.autoupdate", "boolean")),
            verificationConfigSnapshot(
                Map.of("updater.enabled", "false", "updater.autoupdate", "false"),
                Map.of("updater.enabled", "boolean", "updater.autoupdate", "boolean")));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("config", "overrides"),
                orderedStringParameters(
                    Map.entry("node.updater.enabled", List.of("false")),
                    Map.entry("node.updater.autoupdate", List.of("true")))));

    verify(configPort)
        .applyOverrides(Map.of("node.updater.enabled", "false", "node.updater.autoupdate", "true"));
    verify(configPort).applyOverrides(Map.of("node.updater.enabled", "true"));
    verify(configPort, never()).persist();
    assertEquals(400, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"config_override_rejected\",\"message\":\"Rejected config"
            + " overrides: node.updater.autoupdate\"}}",
        response.body());
  }

  @Test
  void route_whenStringArrayConfigOverrideUsesDecodedValue_expectAccepted() {
    String canonicalValue = network.crypta.support.URLEncoder.encode("/home/alice/My Files", false);
    when(configPort.export(EnumSet.of(ConfigSection.CURRENT, ConfigSection.DATA_TYPES)))
        .thenReturn(
            verificationConfigSnapshot(
                Map.of("downloadAllowedDirs", ""), Map.of("downloadAllowedDirs", "stringArray")),
            verificationConfigSnapshot(
                Map.of("downloadAllowedDirs", canonicalValue),
                Map.of("downloadAllowedDirs", "stringArray")));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("config", "overrides"),
                orderedStringParameters(
                    Map.entry("node.downloadAllowedDirs", List.of("/home/alice/My Files")))));

    verify(configPort).applyOverrides(Map.of("node.downloadAllowedDirs", "/home/alice/My Files"));
    verify(configPort, never()).applyOverrides(Map.of("node.downloadAllowedDirs", ""));
    assertEquals(200, response.statusCode());
    assertEquals("{\"operation\":\"apply_overrides\",\"overrideCount\":1}", response.body());
  }

  @Test
  void route_whenStringConfigOverrideIsNormalized_expectAccepted() {
    when(configPort.export(EnumSet.of(ConfigSection.CURRENT, ConfigSection.DATA_TYPES)))
        .thenReturn(
            verificationConfigSnapshot(
                Map.of("updater.URI", "USK@old-key"), Map.of("updater.URI", "string")),
            verificationConfigSnapshot(
                Map.of("updater.URI", CANONICAL_UPDATE_URI), Map.of("updater.URI", "string")));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("config", "overrides"),
                orderedStringParameters(Map.entry("node.updater.URI", List.of(FULL_UPDATE_URI)))));

    verify(configPort).applyOverrides(Map.of("node.updater.URI", FULL_UPDATE_URI));
    assertEquals(200, response.statusCode());
    assertEquals("{\"operation\":\"apply_overrides\",\"overrideCount\":1}", response.body());
  }

  @Test
  void route_whenNormalizedStringConfigOverrideIsIdempotent_expectAccepted() {
    when(configPort.export(EnumSet.of(ConfigSection.CURRENT, ConfigSection.DATA_TYPES)))
        .thenReturn(
            verificationConfigSnapshot(
                Map.of("updater.URI", CANONICAL_UPDATE_URI), Map.of("updater.URI", "string")),
            verificationConfigSnapshot(
                Map.of("updater.URI", CANONICAL_UPDATE_URI), Map.of("updater.URI", "string")));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("config", "overrides"),
                orderedStringParameters(Map.entry("node.updater.URI", List.of(FULL_UPDATE_URI)))));

    verify(configPort).applyOverrides(Map.of("node.updater.URI", FULL_UPDATE_URI));
    assertEquals(200, response.statusCode());
    assertEquals("{\"operation\":\"apply_overrides\",\"overrideCount\":1}", response.body());
  }

  @Test
  void route_whenConfigPersistRequested_expectMutationSummary() {
    PlatformApiResponse response =
        router.route(request("POST", List.of("config", "persist"), Map.of()));

    verify(configPort).persist();
    assertEquals(200, response.statusCode());
    assertEquals("{\"operation\":\"persist\"}", response.body());
  }

  @Test
  void route_whenNetworkThreatLevelMutationRequested_expectPersistedSummary() {
    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("security-levels", "network"),
                Map.of("newLevel", List.of("HIGH"))));

    verify(securityLevelsPort).setNetworkThreatLevel(SecurityNetworkThreatLevel.HIGH);
    verify(configPort).persist();
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"operation\":\"set_network_threat_level\",\"networkThreatLevel\":\"HIGH\"}",
        response.body());
  }

  @Test
  void route_whenNetworkThreatLevelWarningRequested_expectWarningJson() {
    when(securityLevelsPort.networkThreatLevelConfirmWarningHtml(
            SecurityNetworkThreatLevel.LOW, "confirmed"))
        .thenReturn("<p>Needs confirmation</p>");

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("security-levels", "network-warning"),
                Map.of("newLevel", List.of("LOW"))));

    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"newLevel\":\"LOW\",\"confirmationRequired\":true,\"warningHtml\":\"<p>Needs"
            + " confirmation</p>\"}",
        response.body());
  }

  @Test
  void route_whenNetworkThreatLevelMutationRequiresConfirmation_expectConflictJson() {
    when(securityLevelsPort.networkThreatLevelConfirmWarningHtml(
            SecurityNetworkThreatLevel.LOW, "confirmed"))
        .thenReturn("<p>Needs confirmation</p>");

    PlatformApiResponse response =
        router.route(
            request(
                "POST", List.of("security-levels", "network"), Map.of("newLevel", List.of("LOW"))));

    verify(securityLevelsPort, never()).setNetworkThreatLevel(any());
    verify(configPort, never()).persist();
    assertEquals(409, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"network_threat_level_confirmation_required\",\"message\":\"This"
            + " network threat-level change requires server-side confirmation. Retry after"
            + " acknowledging the warning in the Web Shell or use the legacy security page.\"}}",
        response.body());
  }

  @Test
  void route_whenNetworkThreatLevelMutationConfirmedViaCheckbox_expectPersistedSummary() {
    when(securityLevelsPort.networkThreatLevelConfirmWarningHtml(
            SecurityNetworkThreatLevel.LOW, "confirmed"))
        .thenReturn("<p>Needs confirmation</p>");

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("security-levels", "network"),
                Map.of("newLevel", List.of("LOW"), "confirmed", List.of("on"))));

    verify(securityLevelsPort).setNetworkThreatLevel(SecurityNetworkThreatLevel.LOW);
    verify(configPort).persist();
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"operation\":\"set_network_threat_level\",\"networkThreatLevel\":\"LOW\"}",
        response.body());
  }

  @Test
  void route_whenPhysicalThreatLevelMutationRequested_expectPersistedSummary() throws IOException {
    when(securityLevelsPort.snapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.NORMAL,
                SecurityPhysicalThreatLevel.NORMAL,
                false,
                false,
                ""));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("security-levels", "physical"),
                Map.of("newLevel", List.of("MAXIMUM"))));

    verify(securityLevelsPort).deleteMasterPasswordFile();
    verify(securityLevelsPort).setPhysicalThreatLevel(SecurityPhysicalThreatLevel.MAXIMUM);
    verify(configPort).persist();
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"operation\":\"set_physical_threat_level\",\"physicalThreatLevel\":\"MAXIMUM\"}",
        response.body());
  }

  @Test
  void route_whenPhysicalMaximumMutationNeedsConfirmation_expectConflictJson() throws IOException {
    when(securityLevelsPort.snapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.NORMAL,
                SecurityPhysicalThreatLevel.NORMAL,
                true,
                false,
                ""));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("security-levels", "physical"),
                Map.of("newLevel", List.of("MAXIMUM"))));

    verify(securityLevelsPort, never()).deleteMasterPasswordFile();
    verify(securityLevelsPort, never()).setPhysicalThreatLevel(any());
    verify(configPort, never()).persist();
    assertEquals(409, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"physical_threat_level_confirmation_required\",\"message\":\"Changing"
            + " the physical threat level to MAXIMUM can delete queued work. Retry after"
            + " acknowledging the confirmation.\"}}",
        response.body());
  }

  @Test
  void route_whenPhysicalMaximumMutationConfirmed_expectPersistedSummary() throws IOException {
    when(securityLevelsPort.snapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.NORMAL,
                SecurityPhysicalThreatLevel.NORMAL,
                true,
                false,
                ""));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("security-levels", "physical"),
                Map.of("newLevel", List.of("MAXIMUM"), "confirmed", List.of("true"))));

    verify(securityLevelsPort).deleteMasterPasswordFile();
    verify(securityLevelsPort).setPhysicalThreatLevel(SecurityPhysicalThreatLevel.MAXIMUM);
    verify(configPort).persist();
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"operation\":\"set_physical_threat_level\",\"physicalThreatLevel\":\"MAXIMUM\"}",
        response.body());
  }

  @Test
  void route_whenPhysicalThreatLevelMutationNeedsPasswordFlow_expectConflictJson() {
    when(securityLevelsPort.snapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.NORMAL,
                SecurityPhysicalThreatLevel.NORMAL,
                false,
                false,
                ""));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("security-levels", "physical"),
                Map.of("newLevel", List.of("HIGH"))));

    verify(securityLevelsPort, never()).setPhysicalThreatLevel(any());
    verify(configPort, never()).persist();
    assertEquals(409, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"physical_threat_level_password_required\",\"message\":\"Changing"
            + " to or from physical HIGH still requires the legacy password flow. Use the legacy"
            + " security page for this transition.\"}}",
        response.body());
  }

  @Test
  void route_whenPhysicalMaximumMutationFromHigh_expectPersistedSummary() throws IOException {
    when(securityLevelsPort.snapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.NORMAL,
                SecurityPhysicalThreatLevel.HIGH,
                true,
                true,
                "/master.keys"));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("security-levels", "physical"),
                Map.of("newLevel", List.of("MAXIMUM"), "confirmed", List.of("true"))));

    verify(securityLevelsPort).deleteMasterPasswordFile();
    verify(securityLevelsPort).setPhysicalThreatLevel(SecurityPhysicalThreatLevel.MAXIMUM);
    verify(configPort).persist();
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"operation\":\"set_physical_threat_level\",\"physicalThreatLevel\":\"MAXIMUM\"}",
        response.body());
  }

  @Test
  void route_whenLeavingPhysicalMaximum_expectWizardPhysicalSetter() {
    when(securityLevelsPort.snapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.NORMAL,
                SecurityPhysicalThreatLevel.MAXIMUM,
                true,
                false,
                ""));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("security-levels", "physical"),
                Map.of("newLevel", List.of("NORMAL"))));

    verify(firstTimeWizardPort).setPhysicalThreatLevel(SecurityPhysicalThreatLevel.NORMAL);
    verify(securityLevelsPort, never()).setPhysicalThreatLevel(any());
    verify(configPort, never()).persist();
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"operation\":\"set_physical_threat_level\",\"physicalThreatLevel\":\"NORMAL\"}",
        response.body());
  }

  @Test
  void route_whenCoreUpdatesRequested_expectAvailabilityJson() {
    when(coreUpdateActionPort.isCoreUpdaterAvailable()).thenReturn(true);
    when(coreUpdateActionPort.isCoreDownloadAvailable()).thenReturn(true);

    PlatformApiResponse response =
        router.route(request("GET", List.of("updates", "core"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals("{\"available\":true,\"downloadAllowed\":true}", response.body());
  }

  @Test
  void route_whenCoreUpdateDownloadRequested_expectTriggeredSummary() {
    when(coreUpdateActionPort.isCoreUpdaterAvailable()).thenReturn(true);
    when(coreUpdateActionPort.isCoreDownloadAvailable()).thenReturn(true);
    when(coreUpdateActionPort.startCoreDownloadFromUi()).thenReturn(true);

    PlatformApiResponse response =
        router.route(request("POST", List.of("updates", "core", "download"), Map.of()));

    verify(coreUpdateActionPort).startCoreDownloadFromUi();
    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"operation\":\"start_core_download\",\"downloadTriggered\":true}", response.body());
  }

  @Test
  void route_whenCoreUpdateDownloadRequestedWhileUnavailable_expectConflictJson() {
    when(coreUpdateActionPort.isCoreUpdaterAvailable()).thenReturn(false);

    PlatformApiResponse response =
        router.route(request("POST", List.of("updates", "core", "download"), Map.of()));

    assertEquals(409, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"updater_unavailable\",\"message\":\"Core updater is not currently"
            + " available.\"}}",
        response.body());
  }

  @Test
  void route_whenCoreUpdateDownloadRequestedWithoutSelectablePackage_expectConflictJson() {
    when(coreUpdateActionPort.isCoreUpdaterAvailable()).thenReturn(true);
    when(coreUpdateActionPort.isCoreDownloadAvailable()).thenReturn(false);

    PlatformApiResponse response =
        router.route(request("POST", List.of("updates", "core", "download"), Map.of()));

    assertEquals(409, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"core_update_unavailable\",\"message\":\"No selectable core update"
            + " is currently available.\"}}",
        response.body());
  }

  @Test
  void route_whenCoreUpdateDownloadDoesNotStart_expectConflictJson() {
    when(coreUpdateActionPort.isCoreUpdaterAvailable()).thenReturn(true);
    when(coreUpdateActionPort.isCoreDownloadAvailable()).thenReturn(true);
    when(coreUpdateActionPort.startCoreDownloadFromUi()).thenReturn(false);

    PlatformApiResponse response =
        router.route(request("POST", List.of("updates", "core", "download"), Map.of()));

    assertEquals(409, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"core_download_not_started\",\"message\":\"The core download could"
            + " not be started. Refresh updater state and retry.\"}}",
        response.body());
  }

  @Test
  void route_whenFirstTimeWizardRequested_expectSnapshotJson() {
    when(firstTimeWizardPort.snapshot())
        .thenReturn(
            new FirstTimeWizardSnapshot(
                true,
                "2.50",
                "1.25",
                1342177280L,
                "10.00",
                10737418240L,
                12884901888L,
                10L,
                976562L,
                "49.44",
                "2048",
                "1024",
                new FirstTimeWizardCurrentBandwidthLimits(4096L, 1024L),
                -1L));
    when(firstTimeWizardPort.isOpennetEnabled()).thenReturn(true);
    when(firstTimeWizardPort.securitySnapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.HIGH,
                SecurityPhysicalThreatLevel.HIGH,
                false,
                false,
                ""));

    PlatformApiResponse response =
        router.route(request("GET", List.of("wizard", "first-time"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"passwordAlreadySet\":true,\"opennetEnabled\":true,\"currentNetworkThreatLevel\":\"HIGH\",\"currentPhysicalThreatLevel\":\"HIGH\",\"initialStorageLimitGiB\":\"2.50\",\"minStorageLimitGiB\":\"1.25\",\"minStorageLimitBytes\":1342177280,\"maxStorageLimitGiB\":\"10.00\",\"maxStorageLimitBytes\":10737418240,\"legacyMaxStorageLimitBytes\":12884901888,\"minBandwidthKiB\":10,\"maxUploadLimitKiB\":976562,\"minBandwidthMonthlyLimitGiB\":\"49.44\",\"detectedDownloadLimitKiB\":\"2048\",\"detectedUploadLimitKiB\":\"1024\",\"currentBandwidthLimits\":{\"downloadBytes\":4096,\"uploadBytes\":1024},\"autodetectedStorageLimitBytes\":-1}",
        response.body());
  }

  @Test
  void route_whenFirstTimeWizardApplyRequested_expectSubmissionSummary() {
    when(firstTimeWizardPort.snapshot())
        .thenReturn(
            new FirstTimeWizardSnapshot(
                false,
                "2.00",
                "1.25",
                1342177280L,
                "10.00",
                10737418240L,
                10L,
                976562L,
                "49.44",
                "",
                "",
                -1L));
    when(firstTimeWizardPort.securitySnapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.NORMAL,
                SecurityPhysicalThreatLevel.NORMAL,
                false,
                false,
                ""));
    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("wizard", "first-time", "apply"),
                orderedStringParameters(
                    Map.entry("knowSomeone", List.of("on")),
                    Map.entry("downloadLimitKiB", List.of("20000")),
                    Map.entry("uploadLimitKiB", List.of("10000")),
                    Map.entry("storageLimitGiB", List.of("2")),
                    Map.entry("setPassword", List.of("on")),
                    Map.entry("password", List.of("secret")))));

    verify(firstTimeWizardPort)
        .applySubmission(
            new FirstTimeWizardSubmission(
                true, false, false, "20000", "10000", "", "2", true, "secret"));
    assertEquals(200, response.statusCode());
    assertEquals("{\"operation\":\"apply_submission\",\"wizardApplied\":true}", response.body());
  }

  @Test
  void route_whenFirstTimeWizardApplyRequestedWithPreserveBandwidth_expectSubmissionSummary() {
    when(firstTimeWizardPort.snapshot())
        .thenReturn(
            new FirstTimeWizardSnapshot(
                false,
                "2.00",
                "1.25",
                1342177280L,
                "10.00",
                10737418240L,
                10737418240L,
                10L,
                976562L,
                "49.44",
                "",
                "",
                new FirstTimeWizardCurrentBandwidthLimits(4096L, 1024L),
                -1L));
    when(firstTimeWizardPort.securitySnapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.NORMAL,
                SecurityPhysicalThreatLevel.NORMAL,
                false,
                false,
                ""));
    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("wizard", "first-time", "apply"),
                orderedStringParameters(
                    Map.entry("preserveBandwidthSettings", List.of("on")),
                    Map.entry("storageLimitGiB", List.of("2")),
                    Map.entry("setPassword", List.of("on")),
                    Map.entry("password", List.of("secret")))));

    verify(firstTimeWizardPort)
        .applySubmission(
            new FirstTimeWizardSubmission(
                false, false, false, true, "", "", "", "2", true, "secret"));
    assertEquals(200, response.statusCode());
    assertEquals("{\"operation\":\"apply_submission\",\"wizardApplied\":true}", response.body());
  }

  @Test
  void
      route_whenFirstTimeWizardApplyRequestedWithPreserveBandwidthAndNoCurrentBandwidthRow_expectSubmissionSummary() {
    when(firstTimeWizardPort.snapshot())
        .thenReturn(
            new FirstTimeWizardSnapshot(
                false,
                "2.00",
                "1.25",
                1342177280L,
                "10.00",
                10737418240L,
                10L,
                976562L,
                "49.44",
                "",
                "",
                -1L));
    when(firstTimeWizardPort.securitySnapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.NORMAL,
                SecurityPhysicalThreatLevel.NORMAL,
                false,
                false,
                ""));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("wizard", "first-time", "apply"),
                orderedStringParameters(
                    Map.entry("preserveBandwidthSettings", List.of("on")),
                    Map.entry("storageLimitGiB", List.of("2")))));

    verify(firstTimeWizardPort)
        .applySubmission(
            new FirstTimeWizardSubmission(false, false, false, true, "", "", "", "2", false, ""));
    assertEquals(200, response.statusCode());
    assertEquals("{\"operation\":\"apply_submission\",\"wizardApplied\":true}", response.body());
  }

  @Test
  void
      route_whenFirstTimeWizardApplyRequestedFromLowOrMaximumCurrentSecurityWithoutPreserveFlags_expectConflictJson() {
    when(firstTimeWizardPort.snapshot())
        .thenReturn(
            new FirstTimeWizardSnapshot(
                false,
                "2.00",
                "1.25",
                1342177280L,
                "10.00",
                10737418240L,
                10L,
                976562L,
                "49.44",
                "",
                "",
                -1L));
    when(firstTimeWizardPort.securitySnapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.MAXIMUM,
                SecurityPhysicalThreatLevel.NORMAL,
                false,
                false,
                ""));
    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("wizard", "first-time", "apply"),
                orderedStringParameters(
                    Map.entry("downloadLimitKiB", List.of("20000")),
                    Map.entry("uploadLimitKiB", List.of("10000")),
                    Map.entry("storageLimitGiB", List.of("2")))));

    verify(firstTimeWizardPort, never()).applySubmission(any());
    assertEquals(409, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"wizard_current_security_unsupported\",\"message\":\"Current LOW"
            + " or MAXIMUM network threat levels cannot be represented by the wizard controls."
            + " Retry with preserveCurrentNetworkThreatLevel=true or use the dedicated security"
            + " controls.\"}}",
        response.body());
  }

  @Test
  void
      route_whenFirstTimeWizardApplyRequestedFromLowOrMaximumCurrentSecurityWithPreserveFlags_expectSubmissionSummary() {
    when(firstTimeWizardPort.snapshot())
        .thenReturn(
            new FirstTimeWizardSnapshot(
                false,
                "2.00",
                "1.25",
                1342177280L,
                "10.00",
                10737418240L,
                10L,
                976562L,
                "49.44",
                "",
                "",
                -1L));
    when(firstTimeWizardPort.securitySnapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.MAXIMUM,
                SecurityPhysicalThreatLevel.LOW,
                false,
                false,
                ""));
    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("wizard", "first-time", "apply"),
                orderedStringParameters(
                    Map.entry("preserveCurrentNetworkThreatLevel", List.of("on")),
                    Map.entry("preserveCurrentPhysicalThreatLevel", List.of("on")),
                    Map.entry("downloadLimitKiB", List.of("20000")),
                    Map.entry("uploadLimitKiB", List.of("10000")),
                    Map.entry("storageLimitGiB", List.of("2")))));

    verify(firstTimeWizardPort)
        .applySubmission(
            new FirstTimeWizardSubmission(
                false, false, false, false, true, true, "20000", "10000", "", "2", false, ""));
    assertEquals(200, response.statusCode());
    assertEquals("{\"operation\":\"apply_submission\",\"wizardApplied\":true}", response.body());
  }

  @Test
  void route_whenFirstTimeWizardPasswordRequestedAfterPasswordAlreadySet_expectConflictJson() {
    when(firstTimeWizardPort.snapshot())
        .thenReturn(
            new FirstTimeWizardSnapshot(
                true,
                "2.00",
                "1.25",
                1342177280L,
                "10.00",
                10737418240L,
                10L,
                976562L,
                "49.44",
                "",
                "",
                -1L));
    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("wizard", "first-time", "apply"),
                orderedStringParameters(
                    Map.entry("downloadLimitKiB", List.of("20000")),
                    Map.entry("uploadLimitKiB", List.of("10000")),
                    Map.entry("storageLimitGiB", List.of("2")),
                    Map.entry("setPassword", List.of("on")),
                    Map.entry("password", List.of("secret")))));

    verify(firstTimeWizardPort, never()).applySubmission(any());
    assertEquals(409, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"wizard_password_already_set\",\"message\":\"A startup password is"
            + " already set. Use the dedicated security/password flow instead of the first-time"
            + " wizard submission.\"}}",
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

  private static ConfigSnapshot verificationConfigSnapshot(
      Map<String, String> nodeValues, Map<String, String> dataTypes) {
    return new ConfigSnapshot(
        Map.of(
            ConfigSection.CURRENT,
            new ConfigFieldSet(Map.of(), Map.of("node", new ConfigFieldSet(nodeValues, Map.of()))),
            ConfigSection.DATA_TYPES,
            new ConfigFieldSet(Map.of(), Map.of("node", new ConfigFieldSet(dataTypes, Map.of())))));
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
  void route_whenQueueLocalFileInsertRequested_expectCreatedJsonAndDetachedRequest()
      throws Exception {
    Path sourceFile = tempDir.resolve("publisher-file.txt");
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    stubQueueInsertCompatibilityModes();
    when(queueInsertPort.enqueueLocalFileInsert(any())).thenReturn(QueueInsertOutcome.STARTED);

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("queue", "inserts", "file"),
                Map.of(
                    "sourcePath", List.of(sourceFile.toString()),
                    "insertUri", List.of("SSK@publisher-file"),
                    "identifier", List.of("publisher-file-1"),
                    "contentType", List.of("text/plain"),
                    "targetFilename", List.of("publisher-file.txt"),
                    "compatibilityMode", List.of("COMPAT_CURRENT"),
                    "compress", List.of("on"))));

    verify(queueInsertPort)
        .enqueueLocalFileInsert(
            new QueueLocalFileInsertRequest(
                sourceFile.toFile(),
                "SSK@publisher-file",
                "publisher-file-1",
                "text/plain",
                new QueueInsertOptions(true, "COMPAT_1468", null),
                "publisher-file.txt"));
    assertEquals(201, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            orderedJson(
                Map.entry("operation", "create_local_file_insert"),
                Map.entry("sourceType", "file"),
                Map.entry("sourcePath", sourceFile.toString()),
                Map.entry("insertUri", "SSK@publisher-file"),
                Map.entry("identifier", "publisher-file-1"),
                Map.entry("outcome", "STARTED"))),
        response.body());
  }

  @Test
  void route_whenQueueLocalFileInsertRequestedWithoutContentType_expectCryptadGuessedMime()
      throws Exception {
    Path sourceFile = tempDir.resolve("image.avif");
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    stubQueueInsertCompatibilityModes();
    when(queueInsertPort.enqueueLocalFileInsert(any())).thenReturn(QueueInsertOutcome.STARTED);

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("queue", "inserts", "file"),
                Map.of(
                    "sourcePath", List.of(sourceFile.toString()),
                    "insertUri", List.of("CHK@"),
                    "identifier", List.of("publisher-file-2"),
                    "compatibilityMode", List.of("COMPAT_CURRENT"))));

    verify(queueInsertPort)
        .enqueueLocalFileInsert(
            new QueueLocalFileInsertRequest(
                sourceFile.toFile(),
                "CHK@",
                "publisher-file-2",
                "image/avif",
                new QueueInsertOptions(false, "COMPAT_1468", null),
                "image.avif"));
    assertEquals(201, response.statusCode());
  }

  @Test
  void
      route_whenQueueLocalFileInsertRequestedWithDocnamedUriAndTargetFilename_expectTargetSuppressed()
          throws Exception {
    Path sourceFile = tempDir.resolve("publisher-file.txt");
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    stubQueueInsertCompatibilityModes();
    when(queueInsertPort.enqueueLocalFileInsert(any())).thenReturn(QueueInsertOutcome.STARTED);

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("queue", "inserts", "file"),
                Map.of(
                    "sourcePath", List.of(sourceFile.toString()),
                    "insertUri", List.of("KSK@site-name"),
                    "identifier", List.of("publisher-file-3"),
                    "targetFilename", List.of("ignored-name.txt"),
                    "compatibilityMode", List.of("COMPAT_CURRENT"))));

    verify(queueInsertPort)
        .enqueueLocalFileInsert(
            new QueueLocalFileInsertRequest(
                sourceFile.toFile(),
                "KSK@site-name",
                "publisher-file-3",
                "text/plain",
                new QueueInsertOptions(false, "COMPAT_1468", null),
                null));
    assertEquals(201, response.statusCode());
  }

  @Test
  void route_whenQueueLocalFileInsertRequestedWithMalformedContentType_expectBadRequest()
      throws Exception {
    Path sourceFile = tempDir.resolve("publisher-file.txt");

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("queue", "inserts", "file"),
                Map.of(
                    "sourcePath", List.of(sourceFile.toString()),
                    "insertUri", List.of("CHK@"),
                    "identifier", List.of("publisher-file-4"),
                    "contentType", List.of("textplain"),
                    "compatibilityMode", List.of("COMPAT_CURRENT"))));

    verify(queueInsertPort, never()).enqueueLocalFileInsert(any());
    assertEquals(400, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_query_parameter\",\"message\":\"Query parameter"
            + " 'contentType' must be a plausible MIME type.\"}}",
        response.body());
  }

  @Test
  void route_whenQueueLocalDirectoryInsertRequested_expectCreatedJsonAndDetachedRequest()
      throws Exception {
    Path sourceDirectory = tempDir.resolve("publisher-site");
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    stubQueueInsertCompatibilityModes();
    when(queueInsertPort.enqueueLocalDirectoryInsert(any()))
        .thenReturn(QueueInsertOutcome.IDENTIFIER_COLLISION);

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("queue", "inserts", "directory"),
                Map.of(
                    "sourcePath", List.of(sourceDirectory.toString()),
                    "insertUri", List.of("SSK@publisher-site"),
                    "identifier", List.of("publisher-dir-1"),
                    "compatibilityMode", List.of("COMPAT_1468"),
                    "compress", List.of("false"))));

    verify(queueInsertPort)
        .enqueueLocalDirectoryInsert(
            new QueueLocalDirectoryInsertRequest(
                sourceDirectory.toFile(),
                "SSK@publisher-site",
                "publisher-dir-1",
                new QueueInsertOptions(false, "COMPAT_1468", null)));
    assertEquals(201, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            orderedJson(
                Map.entry("operation", "create_local_directory_insert"),
                Map.entry("sourceType", "directory"),
                Map.entry("sourcePath", sourceDirectory.toString()),
                Map.entry("insertUri", "SSK@publisher-site"),
                Map.entry("identifier", "publisher-dir-1"),
                Map.entry("outcome", "IDENTIFIER_COLLISION"))),
        response.body());
  }

  @Test
  void route_whenQueueLocalFileInsertRequestedWithGet_expectMethodNotAllowed() {
    PlatformApiResponse response =
        router.route(request("GET", List.of("queue", "inserts", "file"), Map.of()));

    assertEquals(405, response.statusCode());
    assertEquals(Map.of("Allow", "POST"), response.headers());
    assertEquals(
        "{\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Platform API v1 supports POST"
            + " requests only.\"}}",
        response.body());
  }

  @Test
  void route_whenQueueLocalDirectoryInsertRequestedWithGet_expectMethodNotAllowed() {
    PlatformApiResponse response =
        router.route(request("GET", List.of("queue", "inserts", "directory"), Map.of()));

    assertEquals(405, response.statusCode());
    assertEquals(Map.of("Allow", "POST"), response.headers());
    assertEquals(
        "{\"error\":{\"code\":\"method_not_allowed\",\"message\":\"Platform API v1 supports POST"
            + " requests only.\"}}",
        response.body());
  }

  @Test
  void route_whenCatalogIdMatchesAddAndDeleteRequested_expectCatalogRemovedJson() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);

    PlatformApiResponse response =
        catalogRouter.route(request("DELETE", List.of("app-catalogs", "add"), Map.of()));

    verify(catalogManager).remove("add");
    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            Map.of(
                "catalog", orderedJson(Map.entry("catalogId", "add"), Map.entry("removed", true)))),
        response.body());
  }

  @Test
  void route_whenCatalogIdMatchesRecommendedAndDeleteRequested_expectCatalogRemovedJson()
      throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);

    PlatformApiResponse response =
        catalogRouter.route(request("DELETE", List.of("app-catalogs", "recommended"), Map.of()));

    verify(catalogManager).remove("recommended");
    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(
            Map.of(
                "catalog",
                orderedJson(Map.entry("catalogId", "recommended"), Map.entry("removed", true)))),
        response.body());
  }

  @Test
  void route_whenRecommendedCatalogsRequested_expectRecommendedCatalogEnvelope() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    when(catalogManager.listCatalogs()).thenReturn(List.of());
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(true);

    withFirstPartyCatalogProperties(
        "https://example.invalid/cryptad-app-catalog.properties",
        () -> {
          PlatformApiResponse response =
              catalogRouter.route(request("GET", List.of("app-catalogs", "recommended"), Map.of()));

          assertEquals(200, response.statusCode());
          assertTrue(response.body().contains("\"catalogId\":\"crypta-first-party-beta\""));
          assertTrue(response.body().contains("\"canAdd\":true"));
          assertTrue(response.body().contains("\"trustedCatalogKeyConfigured\":true"));
        });
  }

  @Test
  void route_whenRecommendedCatalogAddRequested_expectVerifiedAddSourcePath() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    String source = "https://example.invalid/cryptad-app-catalog.properties";
    when(catalogManager.listCatalogs()).thenReturn(List.of());
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(true);
    when(catalogManager.addSource(source, "crypta-first-party-beta"))
        .thenReturn(recommendedCatalogSourceSnapshot(source));

    withFirstPartyCatalogProperties(
        source,
        () -> {
          PlatformApiResponse response =
              catalogRouter.route(
                  request(
                      "POST",
                      List.of("app-catalogs", "recommended", "crypta-first-party-beta", "add"),
                      Map.of()));

          assertEquals(201, response.statusCode());
          assertTrue(response.body().contains("\"catalogId\":\"crypta-first-party-beta\""));
          verify(catalogManager).addSource(source, "crypta-first-party-beta");
          verify(appHost, never()).installFromDirectory(any());
        });
  }

  @Test
  void route_whenRecommendedCatalogHasAppNamedAdd_expectCatalogAppDetailJson() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    when(catalogManager.getApp("recommended", "add")).thenReturn(catalogEntry("add", APP_VERSION));
    when(appHost.describe("add")).thenReturn(Optional.empty());
    when(appHost.status("add")).thenReturn(Optional.empty());

    PlatformApiResponse response =
        catalogRouter.route(
            request("GET", List.of("app-catalogs", "recommended", "apps", "add"), Map.of()));

    verify(catalogManager).getApp("recommended", "add");
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"appId\":\"add\""));
    assertTrue(response.body().contains("\"version\":\"" + APP_VERSION + "\""));
  }

  @Test
  void route_whenCatalogAppHasMinimumCryptaVersion_expectComparableBuildVersion() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    when(nodeInfoPort.greeting())
        .thenReturn(
            new NodeGreetingSnapshot(
                "Cryptad", "Cryptad,1481,1.0,1481", 1481, "abc123", true, "gzip", "en"));
    when(catalogManager.listApps("core"))
        .thenReturn(List.of(catalogEntryWithMinimumCryptaVersion()));
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    PlatformApiResponse response =
        catalogRouter.route(request("GET", List.of("app-catalogs", "core", "apps"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"currentCryptaVersion\":\"1481\""));
    assertTrue(
        response
            .body()
            .contains("\"minimumCryptaVersion\":\"" + CATALOG_MINIMUM_CRYPTA_VERSION + "\""));
    assertTrue(response.body().contains("\"status\":\"satisfied\""));
    assertFalse(response.body().contains("Cryptad,1481,1.0,1481"));
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
        PlatformApiJsonWriter.write(Map.of("apps", List.of(summary(true, APP_PID, STARTED_AT)))),
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
        PlatformApiJsonWriter.write(Map.of("app", summary(true, APP_PID, STARTED_AT))),
        response.body());
  }

  @Test
  void route_whenAppPermissionsRequested_expectDeclaredPermissionsAndDeniedCount()
      throws Exception {
    AppAuditLog auditLog = new AppAuditLog();
    PlatformApiRouter auditedRouter =
        new PlatformApiRouter(runtimePorts, appHost, null, null, auditLog);
    auditLog.append(
        new AppAuditEvent(
            STARTED_AT,
            APP_ID,
            "POST",
            "queue",
            "queue.requests.remove",
            List.of("queue.write"),
            PlatformApiAuthSource.APP_TOKEN,
            AppAuditDecision.DENIED,
            403,
            "missing_capability"));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    PlatformApiResponse response =
        auditedRouter.route(request("GET", List.of("apps", APP_ID, "permissions"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"permissions\":[\"network.access\",\"file.read\"]"));
    assertTrue(response.body().contains("\"recentDeniedCount\":1"));
    assertFalse(response.body().contains("token-"));
  }

  @Test
  void route_whenAppUpdatesRequested_expectUpdateEnvelopeAndRollbackSummary() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter updateRouter = routerWithVault(catalogManager);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollbackStatus(APP_ID))
        .thenReturn(Optional.of(new AppRollbackRecord(APP_ID, APP_NAME, "1.0.0")));

    PlatformApiResponse response =
        updateRouter.route(request("GET", List.of("apps", APP_ID, "updates"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"updates\""));
    assertTrue(response.body().contains("\"mode\":\"manual\""));
    assertTrue(response.body().contains("\"previousVersion\":\"1.0.0\""));
    assertFalse(response.body().contains(tempDir.toString()));
    assertFalse(response.body().contains("token-"));
  }

  @Test
  void route_whenSharedAppUpdateServiceProvided_expectSharedSchedulerSummary() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    AppUpdateService sharedService = sharedAppUpdateService(catalogManager);
    PlatformApiRouter updateRouter =
        new PlatformApiRouter(
            runtimePorts,
            appHost,
            catalogManager,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, sharedService, null));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollbackStatus(APP_ID)).thenReturn(Optional.empty());

    PlatformApiResponse response =
        updateRouter.route(request("GET", List.of("apps", APP_ID, "updates"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"message\":\"shared scheduler summary\""));
    assertTrue(response.body().contains("\"concurrency\":\"per-app-serialized\""));
    assertFalse(response.body().contains("Background scheduler is not configured"));
  }

  private AppUpdateService sharedAppUpdateService(AppCatalogManager catalogManager) {
    AppUpdateService sharedService = new AppUpdateService(appHost, catalogManager);
    sharedService.setSchedulerSummaryProvider(
        appId -> {
          LinkedHashMap<String, Object> scheduler = LinkedHashMap.newLinkedHashMap(11);
          scheduler.put("appId", appId);
          scheduler.put("enabled", true);
          scheduler.put("status", "success");
          scheduler.put("lastCheckAt", "2026-05-12T00:00:00Z");
          scheduler.put("nextCheckAt", "2026-05-12T01:00:00Z");
          scheduler.put("lastResult", "success");
          scheduler.put("lastFailureAt", null);
          scheduler.put("failureCount", 0);
          scheduler.put("lastErrorCode", null);
          scheduler.put("message", "shared scheduler summary");
          scheduler.put("concurrency", "per-app-serialized");
          return scheduler;
        });
    return sharedService;
  }

  private AppUpdateService sharedAppUpdateServiceWithMigrationAcknowledgement(
      AppCatalogManager catalogManager, AppDataService appDataService) {
    AppDataMigrationRunner migrationRunner =
        (_, _, _, _) -> new AppDataMigrationRunner.MigrationExecutionResult(true, "passed", 0);
    return new AppUpdateService(
        appHost,
        catalogManager,
        new AppUpdateService.AppUpdateDependencies(
            AppReviewPolicy.DEFAULT,
            TrustedReviewerKeys::empty,
            null,
            appDataService,
            migrationRunner,
            appId -> Map.of("appId", appId, "enabled", false)));
  }

  private AppDataService migrationAppDataService() {
    AppDataService appDataService =
        new AppDataService(
            new InMemoryAppDataStore(), null, new AppDataStoreConfig(128, 16, 4, 4096, 4096, 8));
    appDataService.putRecord(
        APP_ID,
        Map.of(
            "namespace",
            List.of("ui-state"),
            "key",
            List.of("state"),
            "schemaVersion",
            List.of("1"),
            "valueJson",
            List.of("{\"schemaVersion\":1}")));
    return appDataService;
  }

  @Test
  void route_whenAppUpdateStageRequested_expectVerifiedCandidateStaged() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter updateRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    AppCatalogEntry entry = catalogEntry("9.9.9");
    Path scratchDir = tempDir.resolve("app-update-stage-scratch");
    AppCatalogInstallPlan plan = catalogInstallPlan(entry, scratchDir);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalogSourceSnapshot()));
    when(catalogManager.listApps("core")).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);

    PlatformApiResponse response =
        updateRouter.route(request("POST", List.of("apps", APP_ID, "updates", "stage"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"status\":\"staged\""));
    assertTrue(response.body().contains("\"targetVersion\":\"9.9.9\""));
    assertFalse(response.body().contains(tempDir.toString()));
    //noinspection resource
    verify(catalogManager).prepareInstallPlan("core", APP_ID);
  }

  @Test
  void route_whenAppUpdateStageMigrationAcknowledged_expectRollbackIncompatibleMigrationStaged()
      throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    AppDataService appDataService = migrationAppDataService();
    AppUpdateService updateService =
        sharedAppUpdateServiceWithMigrationAcknowledgement(catalogManager, appDataService);
    PlatformApiRouter updateRouter =
        new PlatformApiRouter(
            runtimePorts,
            appHost,
            catalogManager,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, updateService, null, appDataService));
    AppCatalogEntry entry = catalogEntry("9.9.9");
    Path scratchDir = tempDir.resolve("app-update-stage-migration-scratch");
    AppCatalogInstallPlan plan = catalogInstallPlanWithUiStateMigration(entry, scratchDir);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalogSourceSnapshot()));
    when(catalogManager.listApps("core")).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);

    PlatformApiResponse response =
        updateRouter.route(
            request(
                "POST",
                List.of("apps", APP_ID, "updates", "stage"),
                Map.of("migrationAcknowledged", List.of("true"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"status\":\"staged\""));
    assertTrue(response.body().contains("\"dataMigration\""));
    assertTrue(response.body().contains("\"namespace\":\"ui-state\""));
    assertTrue(response.body().contains("\"rollbackCompatible\":false"));
    assertTrue(response.body().contains("\"operatorReviewRequired\":true"));
    assertFalse(response.body().contains("app_data_migration_review_required"));
  }

  @Test
  void route_whenStagedAppUpdateThenAppUninstalled_expectUpdateStateCleared() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter updateRouter = routerWithVault(catalogManager);
    AppCatalogEntry entry = catalogEntry("9.9.9");
    Path scratchDir = tempDir.resolve("app-update-uninstall-stage-scratch");
    try (AppCatalogInstallPlan plan = catalogInstallPlan(entry, scratchDir)) {
      when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
      when(appHost.status(APP_ID)).thenReturn(Optional.empty());
      when(catalogManager.listCatalogs()).thenReturn(List.of(catalogSourceSnapshot()));
      when(catalogManager.listApps("core")).thenReturn(List.of(entry));
      when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);

      PlatformApiResponse stageResponse =
          updateRouter.route(
              request("POST", List.of("apps", APP_ID, "updates", "stage"), Map.of()));
      PlatformApiResponse uninstallResponse =
          updateRouter.route(request("DELETE", List.of("apps", APP_ID), Map.of()));
      PlatformApiResponse summaryResponse =
          updateRouter.route(request("GET", List.of("apps", APP_ID, "updates"), Map.of()));

      assertEquals(200, stageResponse.statusCode());
      assertEquals(200, uninstallResponse.statusCode());
      assertEquals(200, summaryResponse.statusCode());
      assertFalse(Files.exists(scratchDir));
      assertTrue(summaryResponse.body().contains("\"status\":\"none\""));
      assertTrue(summaryResponse.body().contains("\"available\":false"));
      assertFalse(summaryResponse.body().contains("\"status\":\"staged\""));
      assertFalse(summaryResponse.body().contains("\"targetVersion\":\"9.9.9\""));
    }
  }

  @Test
  void route_whenUninstallVaultCleanupFailsAfterCommit_expectUpdateStateCleared() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    var grant =
        vaultService.grantIdentity(
            identity.identityId(),
            APP_ID,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            "operator",
            "test grant",
            null,
            null);
    Files.writeString(
        tempDir.resolve("vault").resolve("grants").resolve(grant.grantId() + ".properties"),
        """
        grantId=%s
        identityId=%s
        appId=%s
        scopes=sign.domain-separated
        status=not-a-status
        createdAt=%s
        updatedAt=%s
        """
            .formatted(
                grant.grantId(),
                grant.identityId(),
                grant.appId(),
                grant.createdAt(),
                grant.updatedAt()));
    vaultService.putSecret(
        APP_ID,
        "api-token",
        "generic",
        "retained-secret".getBytes(java.nio.charset.StandardCharsets.UTF_8),
        Map.of());
    PlatformApiRouter updateRouter =
        new PlatformApiRouter(
            runtimePorts,
            appHost,
            catalogManager,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            vaultService);
    AppCatalogEntry entry = catalogEntry("9.9.9");
    Path scratchDir = tempDir.resolve("app-update-uninstall-vault-cleanup-stage-scratch");
    try (AppCatalogInstallPlan plan = catalogInstallPlan(entry, scratchDir)) {
      when(appHost.describe(APP_ID))
          .thenReturn(Optional.of(installedSnapshot()))
          .thenReturn(Optional.of(installedSnapshot()))
          .thenReturn(Optional.empty())
          .thenReturn(Optional.of(installedSnapshot()));
      when(appHost.status(APP_ID)).thenReturn(Optional.empty());
      when(catalogManager.listCatalogs()).thenReturn(List.of(catalogSourceSnapshot()));
      when(catalogManager.listApps("core")).thenReturn(List.of(entry));
      when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);

      PlatformApiResponse stageResponse =
          updateRouter.route(
              request("POST", List.of("apps", APP_ID, "updates", "stage"), Map.of()));
      PlatformApiResponse uninstallResponse =
          updateRouter.route(request("DELETE", List.of("apps", APP_ID), Map.of()));
      PlatformApiResponse summaryResponse =
          updateRouter.route(request("GET", List.of("apps", APP_ID, "updates"), Map.of()));
      PlatformApiResponse retainedSecretResponse =
          updateRouter.route(
              new PlatformApiRequest(
                  "GET",
                  List.of("app-vault", "secrets", "api-token"),
                  Map.of(),
                  PlatformApiPrincipal.appToken(APP_ID, List.of("vault.secrets.read"))));

      assertEquals(200, stageResponse.statusCode());
      assertEquals(400, uninstallResponse.statusCode());
      assertTrue(uninstallResponse.body().contains("unsupported_grant_status"));
      assertEquals(200, summaryResponse.statusCode());
      assertEquals(403, retainedSecretResponse.statusCode());
      assertTrue(retainedSecretResponse.body().contains("app_vault_access_disabled"));
      assertFalse(retainedSecretResponse.body().contains("retained-secret"));
      assertFalse(Files.exists(scratchDir));
      assertTrue(summaryResponse.body().contains("\"status\":\"none\""));
      assertFalse(summaryResponse.body().contains("\"status\":\"staged\""));
      assertFalse(summaryResponse.body().contains("\"targetVersion\":\"9.9.9\""));
    }
  }

  @Test
  void route_whenUninstallVaultPreBlockFails_expectUpdateStatePreserved() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    Path vaultRoot = tempDir.resolve("vault-preblock-failure");
    AppVaultService vaultService = AppVaultService.open(vaultRoot);
    PlatformApiRouter updateRouter =
        new PlatformApiRouter(
            runtimePorts,
            appHost,
            catalogManager,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            vaultService);
    AppCatalogEntry entry = catalogEntry("9.9.9");
    Path scratchDir = tempDir.resolve("app-update-uninstall-vault-preblock-stage-scratch");
    try (AppCatalogInstallPlan plan = catalogInstallPlan(entry, scratchDir)) {
      when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
      when(appHost.status(APP_ID)).thenReturn(Optional.empty());
      when(catalogManager.listCatalogs()).thenReturn(List.of(catalogSourceSnapshot()));
      when(catalogManager.listApps("core")).thenReturn(List.of(entry));
      when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);

      PlatformApiResponse stageResponse =
          updateRouter.route(
              request("POST", List.of("apps", APP_ID, "updates", "stage"), Map.of()));
      Path accessBlocksRoot = vaultRoot.resolve("app-access-blocks");
      Files.delete(accessBlocksRoot);
      Files.writeString(accessBlocksRoot, "not-a-directory");
      PlatformApiResponse uninstallResponse =
          updateRouter.route(request("DELETE", List.of("apps", APP_ID), Map.of()));
      PlatformApiResponse summaryResponse =
          updateRouter.route(request("GET", List.of("apps", APP_ID, "updates"), Map.of()));

      assertEquals(200, stageResponse.statusCode());
      assertEquals(500, uninstallResponse.statusCode());
      assertTrue(uninstallResponse.body().contains("vault_storage_failed"));
      assertEquals(200, summaryResponse.statusCode());
      assertTrue(summaryResponse.body().contains("\"status\":\"staged\""));
      assertTrue(summaryResponse.body().contains("\"targetVersion\":\"9.9.9\""));
      verify(appHost, never()).uninstall(eq(APP_ID), any(AppUninstallOptions.class));
    }
  }

  @Test
  void route_whenAppUpdateApplyRequestedWhileRunning_expectConflictJson() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter updateRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    AppCatalogEntry entry = catalogEntry("9.9.9");
    Path scratchDir = tempDir.resolve("app-update-apply-scratch");
    AppCatalogInstallPlan plan = catalogInstallPlan(entry, scratchDir);
    Path stagedDir = plan.stagedBundleDirectory();
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.status(APP_ID))
        .thenReturn(Optional.empty())
        .thenReturn(Optional.empty())
        .thenReturn(Optional.of(runningSnapshot()));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalogSourceSnapshot()));
    when(catalogManager.listApps("core")).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    PlatformApiResponse stageResponse =
        updateRouter.route(request("POST", List.of("apps", APP_ID, "updates", "stage"), Map.of()));

    PlatformApiResponse response =
        updateRouter.route(request("POST", List.of("apps", APP_ID, "updates", "apply"), Map.of()));

    assertEquals(200, stageResponse.statusCode());
    assertEquals(409, response.statusCode());
    assertEquals("Conflict", response.reasonPhrase());
    assertTrue(response.body().contains("\"code\":\"app_running\""));
    assertTrue(response.body().contains("App must be stopped before update."));
    verify(appHost, never()).updateFromDirectory(APP_ID, stagedDir);
  }

  @Test
  void route_whenAppUpdatePolicyChanged_expectPolicyEnvelope() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter updateRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));

    PlatformApiResponse response =
        updateRouter.route(
            request(
                "POST",
                List.of("apps", APP_ID, "updates", "policy"),
                Map.of("mode", List.of("stage"))));

    assertEquals(200, response.statusCode());
    assertEquals(
        "{\"policy\":{\"mode\":\"stage\",\"allowedChannels\":[\"stable\"],"
            + "\"automaticStaging\":true,\"automaticApply\":false,"
            + "\"deprecatedAutoUpdatesBlocked\":true}}",
        response.body());
  }

  @Test
  void route_whenAppPrincipalChangesUpdatePolicy_expectDeniedBeforeDispatch() {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    AppAuditLog auditLog = new AppAuditLog();
    PlatformApiRouter updateRouter =
        new PlatformApiRouter(runtimePorts, appHost, catalogManager, null, auditLog);

    PlatformApiResponse response =
        updateRouter.route(
            new PlatformApiRequest(
                "POST",
                List.of("apps", APP_ID, "updates", "policy"),
                Map.of("mode", List.of("stage")),
                PlatformApiPrincipal.appToken(APP_ID, List.of("apps.manage"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
    verifyNoInteractions(appHost, catalogManager);
  }

  @Test
  void route_whenAppPrincipalStagesUpdateWithoutCatalogManage_expectDeniedBeforeDispatch() {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    AppAuditLog auditLog = new AppAuditLog();
    PlatformApiRouter updateRouter =
        new PlatformApiRouter(runtimePorts, appHost, catalogManager, null, auditLog);

    PlatformApiResponse response =
        updateRouter.route(
            new PlatformApiRequest(
                "POST",
                List.of("apps", APP_ID, "updates", "stage"),
                Map.of(),
                PlatformApiPrincipal.appToken(APP_ID, List.of("apps.manage"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
    verifyNoInteractions(appHost, catalogManager);
  }

  @Test
  void route_whenAppAuditRequested_expectRecentTokenFreeAuditEntries() throws Exception {
    AppAuditLog auditLog = new AppAuditLog();
    PlatformApiRouter auditedRouter =
        new PlatformApiRouter(runtimePorts, appHost, null, null, auditLog);
    auditLog.append(
        new AppAuditEvent(
            STARTED_AT,
            APP_ID,
            "GET",
            "node",
            "node.read",
            List.of("node.read"),
            PlatformApiAuthSource.APP_TOKEN,
            AppAuditDecision.ALLOWED,
            200,
            "route_completed"));
    auditLog.append(
        new AppAuditEvent(
            STARTED_AT.plusSeconds(1),
            APP_ID,
            "GET",
            "queue",
            "queue.read",
            List.of("queue.read"),
            PlatformApiAuthSource.APP_BROWSER_SESSION,
            AppAuditDecision.ALLOWED,
            200,
            "route_completed"));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));

    PlatformApiResponse response =
        auditedRouter.route(request("GET", List.of("apps", APP_ID, "audit"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"decision\":\"ALLOWED\""));
    assertTrue(response.body().contains("\"requiredCapabilities\":[\"node.read\"]"));
    assertTrue(response.body().contains("\"authSource\":\"APP_TOKEN\""));
    assertTrue(response.body().contains("\"authSource\":\"APP_BROWSER_SESSION\""));
    assertFalse(response.body().contains("token-"));
  }

  @Test
  void route_whenAppPrincipalHasCapability_expectDispatchAndAllowedAudit() {
    AppAuditLog auditLog = new AppAuditLog();
    PlatformApiRouter auditedRouter =
        new PlatformApiRouter(runtimePorts, appHost, null, null, auditLog);
    when(nodeInfoPort.greeting())
        .thenReturn(new NodeGreetingSnapshot("Crypta", "1.0", 7, "abc123", true, "gzip", "en"));

    PlatformApiResponse response =
        auditedRouter.route(
            appRequest(List.of("node", "greeting"), Map.of(), List.of("node.read")));

    assertEquals(200, response.statusCode());
    List<AppAuditEvent> events = auditLog.recentForApp(APP_ID, 10);
    assertEquals(1, events.size());
    assertEquals(AppAuditDecision.ALLOWED, events.getFirst().decision());
    assertEquals("node.read", events.getFirst().action());
  }

  @Test
  void route_whenBrowserAppPrincipalHasQueueRead_expectQueueReadDispatch() throws Exception {
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queuePagePort.renderPage(new QueuePageRequest(false, false, null, false)))
        .thenReturn(new QueuePageSnapshot("Downloads", "<div>queue</div>"));

    PlatformApiResponse response =
        router.route(
            browserAppRequest(
                "GET",
                List.of("queue"),
                Map.of("page", List.of("downloads")),
                List.of("queue.read")));

    verify(queueCompletionPort).ensureTrackingStarted(false);
    assertEquals(200, response.statusCode());
    LinkedHashMap<String, Object> expected = LinkedHashMap.newLinkedHashMap(6);
    expected.put("page", "downloads");
    expected.put("pageTitle", "Downloads");
    expected.put("contentHtml", "<div>queue</div>");
    expected.put("advancedMode", false);
    expected.put("sortBy", null);
    expected.put("reversed", false);
    assertEquals(PlatformApiJsonWriter.write(expected), response.body());
  }

  @Test
  void route_whenBrowserAppPrincipalLacksPeersWrite_expectForbidden() {
    PlatformApiResponse response =
        router.route(
            browserAppRequest("POST", List.of("peers", "add"), Map.of(), List.of("peers.read")));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
    verifyNoInteractions(peerPort);
  }

  @Test
  void route_whenAppPrincipalMissingCapability_expectForbiddenAndDeniedAudit() {
    AppAuditLog auditLog = new AppAuditLog();
    PlatformApiRouter auditedRouter =
        new PlatformApiRouter(runtimePorts, appHost, null, null, auditLog);

    PlatformApiResponse response =
        auditedRouter.route(
            appRequest(List.of("node", "greeting"), Map.of(), List.of("queue.read")));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
    assertFalse(response.body().contains("secret-token"));
    verifyNoInteractions(nodeInfoPort);
    List<AppAuditEvent> events = auditLog.recentForApp(APP_ID, 10);
    assertEquals(1, events.size());
    assertEquals(AppAuditDecision.DENIED, events.getFirst().decision());
    assertEquals("missing_capability", events.getFirst().reasonCode());
  }

  @Test
  void route_whenAppPrincipalHitsUnsupportedQueueReadShape_expectForbiddenAndDeniedAudit() {
    AppAuditLog auditLog = new AppAuditLog();
    PlatformApiRouter auditedRouter =
        new PlatformApiRouter(runtimePorts, appHost, null, null, auditLog);

    PlatformApiResponse response =
        auditedRouter.route(
            appRequest(List.of("queue", "requests", "remove"), Map.of(), List.of("queue.read")));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
    List<AppAuditEvent> events = auditLog.recentForApp(APP_ID, 10);
    assertEquals(1, events.size());
    assertEquals(AppAuditDecision.DENIED, events.getFirst().decision());
    assertEquals("queue.unmapped", events.getFirst().action());
    assertEquals("unmapped_route", events.getFirst().reasonCode());
  }

  @Test
  void route_whenAppPrincipalHitsUnsupportedAlertsReadShape_expectForbiddenAndDeniedAudit() {
    AppAuditLog auditLog = new AppAuditLog();
    PlatformApiRouter auditedRouter =
        new PlatformApiRouter(runtimePorts, appHost, null, null, auditLog);

    PlatformApiResponse response =
        auditedRouter.route(
            appRequest(List.of("alerts", "42", "dismiss"), Map.of(), List.of("alerts.read")));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
    verifyNoInteractions(alertMutationPort);
    List<AppAuditEvent> events = auditLog.recentForApp(APP_ID, 10);
    assertEquals(1, events.size());
    assertEquals(AppAuditDecision.DENIED, events.getFirst().decision());
    assertEquals("alerts.unmapped", events.getFirst().action());
    assertEquals("unmapped_route", events.getFirst().reasonCode());
  }

  @Test
  void route_whenAppPrincipalHitsUnsupportedConfigReadShape_expectForbiddenAndDeniedAudit() {
    AppAuditLog auditLog = new AppAuditLog();
    PlatformApiRouter auditedRouter =
        new PlatformApiRouter(runtimePorts, appHost, null, null, auditLog);

    PlatformApiResponse response =
        auditedRouter.route(
            appRequest(List.of("config", "overrides"), Map.of(), List.of("config.read")));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
    verifyNoInteractions(configPort);
    List<AppAuditEvent> events = auditLog.recentForApp(APP_ID, 10);
    assertEquals(1, events.size());
    assertEquals(AppAuditDecision.DENIED, events.getFirst().decision());
    assertEquals("config.unmapped", events.getFirst().action());
    assertEquals("unmapped_route", events.getFirst().reasonCode());
  }

  @Test
  void route_whenAppPrincipalHitsUnsupportedAppsReadShape_expectForbiddenAndDeniedAudit() {
    AppAuditLog auditLog = new AppAuditLog();
    PlatformApiRouter auditedRouter =
        new PlatformApiRouter(runtimePorts, appHost, null, null, auditLog);

    PlatformApiResponse response =
        auditedRouter.route(
            appRequest(List.of("apps", APP_ID, "start"), Map.of(), List.of("apps.read")));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
    verifyNoInteractions(appHost);
    List<AppAuditEvent> events = auditLog.recentForApp(APP_ID, 10);
    assertEquals(1, events.size());
    assertEquals(AppAuditDecision.DENIED, events.getFirst().decision());
    assertEquals("apps.unmapped", events.getFirst().action());
    assertEquals("unmapped_route", events.getFirst().reasonCode());
  }

  @Test
  void route_whenAppPrincipalHitsUnsupportedCatalogsReadShape_expectForbiddenAndDeniedAudit() {
    AppAuditLog auditLog = new AppAuditLog();
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter auditedRouter =
        new PlatformApiRouter(runtimePorts, appHost, catalogManager, null, auditLog);

    PlatformApiResponse response =
        auditedRouter.route(
            appRequest(List.of("app-catalogs", "core"), Map.of(), List.of("catalogs.read")));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
    verifyNoInteractions(catalogManager);
    List<AppAuditEvent> events = auditLog.recentForApp(APP_ID, 10);
    assertEquals(1, events.size());
    assertEquals(AppAuditDecision.DENIED, events.getFirst().decision());
    assertEquals("app-catalogs.unmapped", events.getFirst().action());
    assertEquals("unmapped_route", events.getFirst().reasonCode());
  }

  @Test
  void route_whenAppRuntimeRequested_expectRuntimeEnvelopeWithoutToken() throws Exception {
    when(appHost.runtimeStatus(APP_ID))
        .thenReturn(
            new AppRuntimeStatusSnapshot(
                APP_ID,
                AppRuntimeState.RUNNING,
                true,
                APP_PID,
                STARTED_AT,
                null,
                null,
                1,
                1,
                true,
                128L));

    PlatformApiResponse response =
        router.route(request("GET", List.of("apps", APP_ID, "runtime"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(PlatformApiJsonWriter.write(Map.of("runtime", runtimeSummary())), response.body());
    assertFalse(response.body().contains("token"));
  }

  @Test
  void route_whenAppLogsRequested_expectLogsEnvelopeWithoutToken() throws Exception {
    when(appHost.readProcessLogTail(APP_ID, 32))
        .thenReturn(
            new AppProcessLogSnapshot(
                APP_ID, true, true, 32, 128L, "CRYPTAD_APP_TOKEN=[REDACTED]\nready\n", STARTED_AT));

    PlatformApiResponse response =
        router.route(
            request("GET", List.of("apps", APP_ID, "logs"), Map.of("maxBytes", List.of("32"))));

    assertEquals(200, response.statusCode());
    assertEquals(PlatformApiJsonWriter.write(Map.of("logs", logsSummary())), response.body());
    assertFalse(response.body().contains("secret"));
  }

  @Test
  void route_whenAppRuntimePostRequested_expectMethodNotAllowedWithAllowGet() {
    PlatformApiResponse response =
        router.route(request("POST", List.of("apps", APP_ID, "runtime"), Map.of()));

    assertEquals(405, response.statusCode());
    assertEquals(Map.of("Allow", "GET"), response.headers());
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
        PlatformApiJsonWriter.write(Map.of("app", installRouteSummary())), response.body());
  }

  @Test
  void route_whenAppIdMatchesInstallRouteAndDeleteRequested_expectUninstallJson() throws Exception {
    InstalledAppSnapshot installed = installedSnapshot(INSTALL_ROUTE_APP_ID);
    when(appHost.describe(INSTALL_ROUTE_APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(INSTALL_ROUTE_APP_ID)).thenReturn(Optional.empty());

    PlatformApiResponse response =
        routerWithVault().route(request("DELETE", List.of("apps", INSTALL_ROUTE_APP_ID), Map.of()));

    assertEquals(200, response.statusCode());
    assertUninstallSummary(response.body(), INSTALL_ROUTE_APP_ID);
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
                    APP_ID, "Alpha App 2", "2.2.0", "ui/v2.html", true, APP_PID, STARTED_AT))),
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
        PlatformApiJsonWriter.write(Map.of("app", summary(false, null, null))), response.body());
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
            Map.of("app", summaryFor(APP_ID, APP_NAME, "9.9.9", APP_UI_ENTRY, false, null, null))),
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
  void route_whenAppInstallSignatureVerificationFails_expectSanitizedBadRequestJson()
      throws Exception {
    Path stagedDir = stageApp();
    when(appHost.describe(APP_ID)).thenAnswer(_ -> Optional.empty());
    when(appHost.installFromDirectory(stagedDir))
        .thenThrow(
            new AppBundleVerificationException(
                "signature sidecar missing in copied bundle: /srv/node/apps/installed/demo-app"));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(400, response.statusCode());
    assertEquals("Bad Request", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_bundle\",\"message\":\"Staged app bundle must pass"
            + " trusted signature verification.\"}}",
        response.body());
  }

  @Test
  void route_whenAppInstallTrustConfigurationFails_expectInternalErrorJson() throws Exception {
    Path stagedDir = stageApp();
    when(appHost.describe(APP_ID)).thenAnswer(_ -> Optional.empty());
    when(appHost.installFromDirectory(stagedDir))
        .thenThrow(new AppHostConfigurationException("Failed to load trusted app keys file."));

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
        PlatformApiJsonWriter.write(Map.of("app", summary(false, null, null))), response.body());
  }

  @Test
  void route_whenAppStopRequestedDuringRestartBackoff_expectDelegatesStopAndReturnsSummary()
      throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.stop(APP_ID)).thenReturn(true);

    PlatformApiResponse response =
        router.route(request("POST", List.of("apps", APP_ID, "stop"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(Map.of("app", summary(false, null, null))), response.body());
    verify(appHost).stop(APP_ID);
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
        PlatformApiJsonWriter.write(Map.of("app", summary(false, null, null))), response.body());
  }

  @Test
  void route_whenAppUninstallRequested_expectInstalledFalseSummaryJson() throws Exception {
    InstalledAppSnapshot installed = installedSnapshot();
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    PlatformApiResponse response =
        routerWithVault().route(request("DELETE", List.of("apps", APP_ID), Map.of()));

    assertEquals(200, response.statusCode());
    assertUninstallSummary(response.body(), APP_ID);
  }

  @Test
  void route_whenAppManifestUnreadableDuringUninstallAndVaultUnavailable_expectConflictJson()
      throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenThrow(new IOException("corrupt manifest"));

    PlatformApiResponse response =
        router.route(request("DELETE", List.of("apps", APP_ID), Map.of()));

    assertEquals(409, response.statusCode());
    assertEquals("Conflict", response.reasonPhrase());
    assertEquals(
        "{\"error\":{\"code\":\"app_vault_unavailable\",\"message\":\"App vault cleanup is"
            + " unavailable; app uninstall cannot safely proceed.\"}}",
        response.body());
  }

  @Test
  void route_whenAppUninstallRacesToMissingAfterVaultBlock_expectCleanupSummaryJson()
      throws Exception {
    InstalledAppSnapshot installed = installedSnapshot();
    when(appHost.describe(APP_ID)).thenAnswer(new TwoStepOptionalAnswer<>(installed, null));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    doThrow(new AppHostException("app is not installed: alpha"))
        .when(appHost)
        .uninstall(APP_ID, AppUninstallOptions.removeAll());

    PlatformApiResponse response =
        routerWithVault().route(request("DELETE", List.of("apps", APP_ID), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals("OK", response.reasonPhrase());
    assertUninstallSummary(response.body(), APP_ID);
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
        .uninstall(APP_ID, AppUninstallOptions.removeAll());

    PlatformApiResponse response =
        routerWithVault().route(request("DELETE", List.of("apps", APP_ID), Map.of()));

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

  @Test
  void route_whenCatalogInstallSucceedsAndCleanupFails_expectCreatedJson() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    AppCatalogInstallPlan plan = mock(AppCatalogInstallPlan.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    Path stagedDir = tempDir.resolve("catalog-install-stage");
    InstalledAppSnapshot installed = installedSnapshot();
    when(catalogManager.getApp("core", APP_ID)).thenReturn(catalogEntry(APP_VERSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(plan.entry()).thenReturn(catalogEntry(APP_VERSION));
    when(plan.stagedBundleDirectory()).thenReturn(stagedDir);
    when(appHost.installFromDirectory(stagedDir)).thenReturn(installed);
    doThrow(new IOException("cleanup failed")).when(plan).close();

    PlatformApiResponse response =
        catalogRouter.route(
            request("POST", List.of("app-catalogs", "core", "apps", APP_ID, "install"), Map.of()));

    assertEquals(201, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(Map.of("app", catalogSummary(APP_VERSION))), response.body());
  }

  @Test
  void route_whenCatalogInstallRepeated_expectConflictWithoutPreparingPlan() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(catalogEntry(APP_VERSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));

    PlatformApiResponse response =
        catalogRouter.route(
            request("POST", List.of("app-catalogs", "core", "apps", APP_ID, "install"), Map.of()));

    assertEquals(409, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"app_conflict\",\"message\":\"app already installed: alpha\"}}",
        response.body());
    //noinspection resource
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void route_whenCatalogInstallStaticUiEntryInvalid_expectInvalidBundle() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    AppCatalogInstallPlan plan = mock(AppCatalogInstallPlan.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    Path stagedDir = tempDir.resolve("catalog-invalid-static-ui-install");
    when(catalogManager.getApp("core", APP_ID)).thenReturn(catalogEntry(APP_VERSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(plan.entry()).thenReturn(catalogEntry(APP_VERSION));
    when(plan.stagedBundleDirectory()).thenReturn(stagedDir);
    when(appHost.installFromDirectory(stagedDir))
        .thenThrow(
            new AppHostException(
                "app.ui.entry does not resolve to a file in copied bundle: static/index.html"));

    PlatformApiResponse response =
        catalogRouter.route(
            request("POST", List.of("app-catalogs", "core", "apps", APP_ID, "install"), Map.of()));

    assertEquals(400, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_bundle\",\"message\":\"Catalog app bundle failed"
            + " AppHost validation.\"}}",
        response.body());
    verify(plan).close();
  }

  @Test
  void route_whenCatalogUpdateSucceedsAndCleanupFails_expectUpdatedJson() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    AppCatalogInstallPlan plan = mock(AppCatalogInstallPlan.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    Path stagedDir = tempDir.resolve("catalog-update-stage");
    InstalledAppSnapshot updated = installedSnapshot(APP_ID, APP_NAME, "9.9.9", APP_UI_ENTRY);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(catalogEntry("9.9.9"));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(plan.entry()).thenReturn(catalogEntry("9.9.9"));
    when(plan.stagedBundleDirectory()).thenReturn(stagedDir);
    when(appHost.updateFromDirectory(APP_ID, stagedDir)).thenReturn(updated);
    doThrow(new IOException("cleanup failed")).when(plan).close();

    PlatformApiResponse response =
        catalogRouter.route(
            request("POST", List.of("app-catalogs", "core", "apps", APP_ID, "update"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(Map.of("app", catalogSummary("9.9.9"))), response.body());
  }

  @Test
  void route_whenCatalogUpdateTargetMissing_expectNotFoundWithoutPreparingPlan() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(catalogEntry("9.9.9"));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiResponse response =
        catalogRouter.route(
            request("POST", List.of("app-catalogs", "core", "apps", APP_ID, "update"), Map.of()));

    assertEquals(404, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"app_not_found\",\"message\":\"App not found.\"}}", response.body());
    //noinspection resource
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void route_whenCatalogUpdateStaticUiEntryInvalid_expectInvalidBundle() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    AppCatalogInstallPlan plan = mock(AppCatalogInstallPlan.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    Path stagedDir = tempDir.resolve("catalog-invalid-static-ui-update");
    when(catalogManager.getApp("core", APP_ID)).thenReturn(catalogEntry("9.9.9"));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(plan.entry()).thenReturn(catalogEntry("9.9.9"));
    when(plan.stagedBundleDirectory()).thenReturn(stagedDir);
    when(appHost.updateFromDirectory(APP_ID, stagedDir))
        .thenThrow(new AppHostException("app.ui.entry must not traverse links in copied bundle"));

    PlatformApiResponse response =
        catalogRouter.route(
            request("POST", List.of("app-catalogs", "core", "apps", APP_ID, "update"), Map.of()));

    assertEquals(400, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_bundle\",\"message\":\"Catalog app bundle failed"
            + " AppHost validation.\"}}",
        response.body());
    verify(plan).close();
  }

  @Test
  void route_whenCatalogUpdateInstalledManifestUnreadable_expectUpdatedJson() throws Exception {
    AppCatalogManager catalogManager = mock(AppCatalogManager.class);
    AppCatalogInstallPlan plan = mock(AppCatalogInstallPlan.class);
    PlatformApiRouter catalogRouter = new PlatformApiRouter(runtimePorts, appHost, catalogManager);
    Path stagedDir = tempDir.resolve("catalog-repair-stage");
    InstalledAppSnapshot updated = installedSnapshot(APP_ID, APP_NAME, "9.9.9", APP_UI_ENTRY);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(catalogEntry("9.9.9"));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenThrow(new IOException("corrupt manifest"));
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(plan.entry()).thenReturn(catalogEntry("9.9.9"));
    when(plan.stagedBundleDirectory()).thenReturn(stagedDir);
    when(appHost.updateFromDirectory(APP_ID, stagedDir)).thenReturn(updated);

    PlatformApiResponse response =
        catalogRouter.route(
            request("POST", List.of("app-catalogs", "core", "apps", APP_ID, "update"), Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(
        PlatformApiJsonWriter.write(Map.of("app", catalogSummary("9.9.9"))), response.body());
    //noinspection resource
    verify(catalogManager).prepareInstallPlan("core", APP_ID);
    verify(appHost).updateFromDirectory(APP_ID, stagedDir);
  }

  private static PlatformApiRequest request(
      String method, List<String> pathSegments, Map<String, List<String>> queryParameters) {
    return new PlatformApiRequest(method, pathSegments, queryParameters);
  }

  private static PlatformApiRequest appRequest(
      List<String> pathSegments,
      Map<String, List<String>> queryParameters,
      List<String> permissions) {
    return new PlatformApiRequest(
        "GET", pathSegments, queryParameters, PlatformApiPrincipal.appToken(APP_ID, permissions));
  }

  private static PlatformApiRequest browserAppRequest(
      String method,
      List<String> pathSegments,
      Map<String, List<String>> queryParameters,
      List<String> permissions) {
    return new PlatformApiRequest(
        method,
        pathSegments,
        queryParameters,
        PlatformApiPrincipal.appBrowserSession(APP_ID, permissions));
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

  private AppCatalogInstallPlan catalogInstallPlan(AppCatalogEntry entry, Path scratchDir)
      throws IOException {
    Path stagedDir = scratchDir.resolve("bundle");
    Files.createDirectories(stagedDir);
    Files.writeString(
        stagedDir.resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch
        app.permissions=%s
        """
            .formatted(
                entry.appId(),
                entry.name(),
                entry.version(),
                String.join(",", entry.permissions())));
    return new AppCatalogInstallPlan("core", entry, stagedDir, scratchDir);
  }

  private AppCatalogInstallPlan catalogInstallPlanWithUiStateMigration(
      AppCatalogEntry entry, Path scratchDir) throws IOException {
    Path stagedDir = scratchDir.resolve("bundle");
    Files.createDirectories(stagedDir);
    Files.writeString(
        stagedDir.resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch
        app.permissions=%s
        app.data.schema.current=2
        app.data.schema.namespaces=ui-state
        app.data.schema.namespace.ui-state.current=2
        app.data.migrations=ui-state-v1-v2
        app.data.migration.ui-state-v1-v2.namespace=ui-state
        app.data.migration.ui-state-v1-v2.from=1
        app.data.migration.ui-state-v1-v2.to=2
        app.data.migration.ui-state-v1-v2.command=bin/migrate-ui-state.sh
        app.data.migration.ui-state-v1-v2.rollbackCompatible=false
        app.data.migration.ui-state-v1-v2.requiresStopped=true
        app.data.migration.ui-state-v1-v2.description=Upgrade UI state to schema v2.
        """
            .formatted(
                entry.appId(),
                entry.name(),
                entry.version(),
                String.join(",", entry.permissions())));
    return new AppCatalogInstallPlan("core", entry, stagedDir, scratchDir);
  }

  private AppCatalogEntry catalogEntry(String version) {
    return catalogEntry(APP_ID, version);
  }

  private AppCatalogEntry catalogEntry(String appId, String version) {
    return new AppCatalogEntry(
        appId,
        APP_NAME,
        version,
        "Catalog app summary",
        tempDir.resolve("artifact.zip").toUri(),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of("network.access"));
  }

  private AppCatalogSourceSnapshot catalogSourceSnapshot() {
    return new AppCatalogSourceSnapshot(
        "core",
        "Core Apps",
        URI.create("https://example.invalid/cryptad-app-catalog.properties"),
        STARTED_AT,
        1,
        STARTED_AT,
        STARTED_AT,
        STARTED_AT,
        STARTED_AT,
        AppCatalogFetchStatus.SUCCESS,
        Optional.empty(),
        Optional.empty(),
        Optional.of("https://example.invalid/cryptad-app-catalog.properties"),
        Optional.empty());
  }

  private AppCatalogSourceSnapshot recommendedCatalogSourceSnapshot(String source) {
    return new AppCatalogSourceSnapshot(
        "crypta-first-party-beta",
        "Crypta First-Party Beta Catalog",
        URI.create(source),
        STARTED_AT,
        3,
        STARTED_AT,
        STARTED_AT,
        STARTED_AT,
        STARTED_AT,
        AppCatalogFetchStatus.SUCCESS,
        Optional.empty(),
        Optional.empty(),
        Optional.of(source),
        Optional.of(FIRST_PARTY_TRUSTED_KEY_ID));
  }

  private static void withFirstPartyCatalogProperties(String source, ThrowingRunnable action)
      throws Exception {
    String previousEnabled = System.getProperty("cryptad.firstPartyCatalog.enabled");
    String previousSource = System.getProperty("cryptad.firstPartyCatalog.source");
    String previousTrustedKeyId =
        System.getProperty("cryptad.firstPartyCatalog.trustedCatalogKeyId");
    try {
      System.setProperty("cryptad.firstPartyCatalog.enabled", "true");
      System.setProperty("cryptad.firstPartyCatalog.source", source);
      System.setProperty(
          "cryptad.firstPartyCatalog.trustedCatalogKeyId", FIRST_PARTY_TRUSTED_KEY_ID);
      action.run();
    } finally {
      restoreSystemProperty("cryptad.firstPartyCatalog.enabled", previousEnabled);
      restoreSystemProperty("cryptad.firstPartyCatalog.source", previousSource);
      restoreSystemProperty("cryptad.firstPartyCatalog.trustedCatalogKeyId", previousTrustedKeyId);
    }
  }

  private static void restoreSystemProperty(String key, String previousValue) {
    if (previousValue == null) {
      System.clearProperty(key);
    } else {
      System.setProperty(key, previousValue);
    }
  }

  @FunctionalInterface
  private interface ThrowingRunnable {
    void run() throws Exception;
  }

  private AppCatalogEntry catalogEntryWithMinimumCryptaVersion() {
    return new AppCatalogEntry(
        APP_ID,
        APP_NAME,
        APP_VERSION,
        "Catalog app summary",
        null,
        null,
        null,
        List.of(),
        new AppCatalogCompatibilityMetadata(CATALOG_MINIMUM_CRYPTA_VERSION),
        AppCatalogReviewMetadata.EMPTY,
        AppCatalogChangelog.EMPTY,
        List.of(),
        URI.create("https://example.invalid/artifact.zip"),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of("network.access"),
        Map.of());
  }

  private static Map<String, Object> summary(boolean running, Long pid, Instant startedAt) {
    return summaryFor(APP_ID, APP_NAME, APP_VERSION, APP_UI_ENTRY, running, pid, startedAt);
  }

  private static Map<String, Object> catalogSummary(String appVersion) {
    LinkedHashMap<String, Object> summary = LinkedHashMap.newLinkedHashMap(12);
    summary.put("appId", APP_ID);
    summary.put("name", APP_NAME);
    summary.put("version", appVersion);
    summary.put("uiMode", uiMode(APP_UI_ENTRY));
    summary.put("uiEntry", APP_UI_ENTRY);
    summary.put("uiUrl", uiUrl(APP_ID, APP_UI_ENTRY));
    summary.put("permissions", List.of("network.access", "file.read"));
    summary.put("apiCompatibility", undeclaredApiCompatibilityForLegacyPermissions());
    summary.put("installed", true);
    summary.put("running", false);
    summary.put("pid", null);
    summary.put("startedAt", null);
    return summary;
  }

  private static Map<String, Object> installRouteSummary() {
    return summaryFor(INSTALL_ROUTE_APP_ID, APP_NAME, APP_VERSION, APP_UI_ENTRY, false, null, null);
  }

  private static Map<String, Object> runtimeSummary() {
    LinkedHashMap<String, Object> summary = LinkedHashMap.newLinkedHashMap(14);
    summary.put("appId", APP_ID);
    summary.put("state", "RUNNING");
    summary.put("running", true);
    summary.put("pid", APP_PID);
    summary.put("startedAt", STARTED_AT.toString());
    summary.put("lastExitAt", null);
    summary.put("lastExitCode", null);
    summary.put("restartCount", 1);
    summary.put("currentRestartAttempt", 1);
    summary.put("logAvailable", true);
    summary.put("logSizeBytes", 128L);
    summary.put("sandbox", sandboxSummary());
    summary.put("quota", unlimitedQuotaSummary());
    summary.put("warnings", List.of());
    return summary;
  }

  private static Map<String, Object> logsSummary() {
    LinkedHashMap<String, Object> summary = LinkedHashMap.newLinkedHashMap(7);
    summary.put("appId", APP_ID);
    summary.put("available", true);
    summary.put("truncated", true);
    summary.put("maxBytes", 32);
    summary.put("sizeBytes", 128L);
    summary.put("text", "CRYPTAD_APP_TOKEN=[REDACTED]\nready\n");
    summary.put("lastModifiedAt", STARTED_AT.toString());
    return summary;
  }

  private static Map<String, Object> summaryFor(
      String appId,
      String appName,
      String appVersion,
      String appUiEntry,
      boolean running,
      Long pid,
      Instant startedAt) {
    LinkedHashMap<String, Object> summary = LinkedHashMap.newLinkedHashMap(21);
    summary.put("appId", appId);
    summary.put("name", appName);
    summary.put("version", appVersion);
    summary.put("uiMode", uiMode(appUiEntry));
    summary.put("uiEntry", appUiEntry);
    summary.put("uiUrl", uiUrl(appId, appUiEntry));
    summary.put("uiOrigin", null);
    summary.put("uiOriginMode", null);
    summary.put("uiOriginStatus", null);
    summary.put("sameOriginFallbackUrl", sameOriginFallbackUrl(appId, appUiEntry));
    summary.put("permissions", List.of("network.access", "file.read"));
    summary.put("apiCompatibility", undeclaredApiCompatibilityForLegacyPermissions());
    summary.put("quota", manifestQuotaSummary());
    summary.put("sandbox", sandboxSummary());
    summary.put("installed", true);
    summary.put("running", running);
    summary.put("pid", pid);
    summary.put("startedAt", startedAt == null ? null : startedAt.toString());
    summary.put("recentDeniedCount", 0L);
    summary.put("audit", emptyAuditSummary(appId));
    summary.put("vault", Map.of("available", false));
    return summary;
  }

  private static void assertUninstallSummary(String body, String appId) {
    assertTrue(body.contains("\"appId\":\"" + appId + "\""));
    assertTrue(body.contains("\"installed\":false"));
    assertTrue(body.contains("\"running\":false"));
    assertTrue(body.contains("\"vault\":{"));
    assertTrue(body.contains("\"available\":true"));
    assertFalse(body.contains("secret-token"));
  }

  private static Map<String, Object> undeclaredApiCompatibilityForLegacyPermissions() {
    return undeclaredApiCompatibility(
        List.of(
            "Unknown manifest permission: file.read.",
            "Unknown manifest permission: network.access."));
  }

  private static Map<String, Object> undeclaredApiCompatibility(List<String> warnings) {
    LinkedHashMap<String, Object> compatibility = LinkedHashMap.newLinkedHashMap(8);
    compatibility.put("minimumVersion", null);
    compatibility.put("maximumTestedVersion", null);
    compatibility.put("currentVersion", PlatformApiContract.current().contractVersion());
    compatibility.put("optionalCapabilities", List.of());
    compatibility.put("experimentalCapabilitiesAccepted", false);
    compatibility.put("declared", false);
    compatibility.put("status", "unknown");
    compatibility.put("warnings", warnings);
    return compatibility;
  }

  private static Map<String, Object> emptyAuditSummary(String appId) {
    LinkedHashMap<String, Object> audit = LinkedHashMap.newLinkedHashMap(4);
    audit.put("appId", appId);
    audit.put("boundedEventLimit", AppAuditLog.DEFAULT_APP_EVENT_LIMIT);
    audit.put("recentDeniedCount", 0L);
    audit.put("events", List.of());
    return audit;
  }

  private static Map<String, Object> sandboxSummary() {
    LinkedHashMap<String, Object> sandbox = LinkedHashMap.newLinkedHashMap(7);
    sandbox.put("mode", "none");
    sandbox.put("required", false);
    sandbox.put("supportLevel", "none");
    sandbox.put("provider", "no-sandbox");
    sandbox.put("active", false);
    sandbox.put("reason", "App is running without OS sandbox isolation");
    sandbox.put("warnings", List.of("App is running without OS sandbox isolation"));
    return sandbox;
  }

  private static AppRuntimeStatusSnapshot stoppedRuntimeStatus(String appId) {
    return new AppRuntimeStatusSnapshot(
        appId,
        AppRuntimeState.STOPPED,
        false,
        null,
        null,
        null,
        null,
        0,
        0,
        false,
        null,
        AppSandboxProviders.inactiveStatus(AppSandboxPolicy.defaults()),
        manifestQuotaStatus(),
        List.of());
  }

  private static AppQuotaStatus manifestQuotaStatus() {
    return new AppQuotaStatus(
        new AppQuotaPolicy(
            MANIFEST_DATA_QUOTA_BYTES,
            MANIFEST_CACHE_QUOTA_BYTES,
            AppHost.DEFAULT_PROCESS_LOG_MAX_BYTES),
        new AppQuotaUsage(0L, 0L, null),
        List.of());
  }

  private static Map<String, Object> manifestQuotaSummary() {
    LinkedHashMap<String, Object> quota = LinkedHashMap.newLinkedHashMap(13);
    quota.put("dataBytes", MANIFEST_DATA_QUOTA_BYTES);
    quota.put("cacheBytes", MANIFEST_CACHE_QUOTA_BYTES);
    quota.put("effectiveDataBytes", MANIFEST_DATA_QUOTA_BYTES);
    quota.put("effectiveCacheBytes", MANIFEST_CACHE_QUOTA_BYTES);
    quota.put("dataUsageBytes", 0L);
    quota.put("cacheUsageBytes", 0L);
    quota.put("dataQuotaEnforced", true);
    quota.put("cacheQuotaEnforced", true);
    quota.put("dataOverLimit", false);
    quota.put("cacheOverLimit", false);
    quota.put("processLogMaxBytes", AppHost.DEFAULT_PROCESS_LOG_MAX_BYTES);
    quota.put("processLogSizeBytes", null);
    quota.put("warnings", List.of());
    return quota;
  }

  private static Map<String, Object> unlimitedQuotaSummary() {
    LinkedHashMap<String, Object> quota = LinkedHashMap.newLinkedHashMap(13);
    quota.put("dataBytes", null);
    quota.put("cacheBytes", null);
    quota.put("effectiveDataBytes", null);
    quota.put("effectiveCacheBytes", null);
    quota.put("dataUsageBytes", 0L);
    quota.put("cacheUsageBytes", 0L);
    quota.put("dataQuotaEnforced", false);
    quota.put("cacheQuotaEnforced", false);
    quota.put("dataOverLimit", false);
    quota.put("cacheOverLimit", false);
    quota.put("processLogMaxBytes", AppHost.DEFAULT_PROCESS_LOG_MAX_BYTES);
    quota.put("processLogSizeBytes", null);
    quota.put("warnings", List.of());
    return quota;
  }

  private static String uiMode(String appUiEntry) {
    if (appUiEntry == null) {
      return "none";
    }
    return appUiEntry.startsWith("/") ? "shell-panel" : "static";
  }

  private static String uiUrl(String appId, String appUiEntry) {
    return switch (uiMode(appUiEntry)) {
      case "none" -> null;
      case "shell-panel" -> appUiEntry;
      case "static" -> staticUiUrl(appId, appUiEntry);
      default -> throw new IllegalArgumentException("unexpected UI mode");
    };
  }

  private static String sameOriginFallbackUrl(String appId, String appUiEntry) {
    return switch (uiMode(appUiEntry)) {
      case "none" -> null;
      case "shell-panel" -> appUiEntry;
      case "static" -> "/apps/" + appId + "/";
      default -> throw new IllegalArgumentException("unexpected UI mode");
    };
  }

  private static String staticUiUrl(String appId, String appUiEntry) {
    int lastSlash = appUiEntry.lastIndexOf('/');
    if (lastSlash < 0) {
      return "/apps/" + appId + "/";
    }
    return "/apps/" + appId + "/" + appUiEntry.substring(0, lastSlash + 1);
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
