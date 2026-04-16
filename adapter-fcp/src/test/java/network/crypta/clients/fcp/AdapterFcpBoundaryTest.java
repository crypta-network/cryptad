package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AdapterFcpBoundaryTest {
  private static final String MODULE_NAME = "adapter-fcp";
  private static final Path ROOT_FCP_MAIN_JAVA =
      Path.of("src", "main", "java", "network", "crypta", "clients", "fcp");
  private static final Path ROOT_FCP_BRIDGE_MAIN_JAVA =
      Path.of("src", "main", "java", "network", "crypta", "clients", "fcp", "bridge");
  private static final Path ADAPTER_FCP_BRIDGE_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "clients", "fcp", "bridge");
  private static final Path ADAPTER_FCP_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "clients", "fcp");
  private static final Path ADAPTER_BUILD_FILE = Path.of(MODULE_NAME, "build.gradle.kts");
  private static final Path BRIDGE_BUILD_FILE = Path.of("bridge-fcp-runtime", "build.gradle.kts");
  private static final Path ADD_PEER_SOURCE = ADAPTER_FCP_MAIN_JAVA.resolve("AddPeer.java");
  private static final Path CLIENT_GET_SOURCE = ADAPTER_FCP_MAIN_JAVA.resolve("ClientGet.java");
  private static final Path CLIENT_GET_EVENT_HANDLING_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetEventHandling.java");
  private static final Path CLIENT_GET_FACTORY_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetFactory.java");
  private static final Path CLIENT_GET_GETTER_FACTORY_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetGetterFactory.java");
  private static final Path CLIENT_GET_LIFECYCLE_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetLifecycle.java");
  private static final Path CLIENT_GET_PERSISTENCE_CODEC_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetPersistenceCodec.java");
  private static final Path CLIENT_GET_MESSAGE_REPLAY_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetMessageReplay.java");
  private static final Path CLIENT_GET_PERSISTENCE_IO_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetPersistenceIO.java");
  private static final Path CLIENT_GET_RESTART_COORDINATOR_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetRestartCoordinator.java");
  private static final Path CLIENT_GET_STATE_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetState.java");
  private static final Path CLIENT_GET_STATUS_REPORTER_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetStatusReporter.java");
  private static final Path CLIENT_GET_STATUS_BUILDER_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetStatusSnapshotBuilder.java");
  private static final Path CLIENT_GET_RETURN_PLANNER_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetReturnPlanner.java");
  private static final Path CLIENT_GET_SETUP_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetSetup.java");
  private static final Path CLIENT_GET_STATUS_SNAPSHOT_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetStatusSnapshot.java");
  private static final Path DOWNLOAD_CONTEXT_SNAPSHOT_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("DownloadContextSnapshot.java");
  private static final Path DOWNLOAD_REQUEST_STATUS_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("DownloadRequestStatus.java");
  private static final Path DOWNLOAD_REQUEST_STATUS_DETAILS_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("DownloadRequestStatusDetails.java");
  private static final Path CLIENT_REQUEST_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientRequest.java");
  private static final Path FCP_SERVER_SOURCE = ADAPTER_FCP_MAIN_JAVA.resolve("FCPServer.java");
  private static final Path FCP_CONNECTION_HANDLER_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("FCPConnectionHandler.java");
  private static final Path FCP_FETCH_RUNTIME_SUPPORT_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("FcpFetchRuntimeSupport.java");
  private static final Path FCP_MESSAGE_RUNTIME_SUPPORT_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("FcpMessageRuntimeSupport.java");
  private static final Path FCP_SERVER_PERSISTENT_OPS_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("FcpServerPersistentOps.java");
  private static final Path FCP_SERVER_RUNTIME_SUPPORT_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("FcpServerRuntimeSupport.java");
  private static final Path FILTER_MESSAGE_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("FilterMessage.java");
  private static final Path FCP_MESSAGE_SOURCE = ADAPTER_FCP_MAIN_JAVA.resolve("FCPMessage.java");
  private static final Path CLIENT_PUT_COMPLEX_DIR_MESSAGE_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientPutComplexDirMessage.java");
  private static final Path CLIENT_PUT_SOURCE = ADAPTER_FCP_MAIN_JAVA.resolve("ClientPut.java");
  private static final Path CLIENT_PUT_DIR_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientPutDir.java");
  private static final Path CLIENT_PUT_PREPARED_DATA_FACTORY_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("ClientPutPreparedDataFactory.java");
  private static final Path PERSISTENT_PUT_DIR_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("PersistentPutDir.java");
  private static final Path FCP_CONNECTION_INPUT_HANDLER_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("FCPConnectionInputHandler.java");
  private static final Path FCP_SERVER_DEPENDENCIES_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("FcpServerDependencies.java");
  private static final Path COMPATIBILITY_MODE_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("CompatibilityMode.java");
  private static final Path FCP_COMPATIBILITY_MODE_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("FcpCompatibilityMode.java");
  private static final Path FCP_COMPATIBILITY_ANALYSIS_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("FcpCompatibilityAnalysis.java");
  private static final Path FCP_INSERT_CONTEXT_HANDLE_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("FcpInsertContextHandle.java");
  private static final Path DEFAULT_FCP_INSERT_CONTEXT_HANDLE_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("DefaultFcpInsertContextHandle.java");
  private static final Path PERSISTENT_REQUEST_CLIENT_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("PersistentRequestClient.java");
  private static final Path REQUEST_STATUS_CACHE_SOURCE =
      ADAPTER_FCP_MAIN_JAVA.resolve("RequestStatusCache.java");
  private static final Set<Path> INSERT_FAMILY_SEAM_SOURCES =
      Set.of(
          ADAPTER_FCP_MAIN_JAVA.resolve("FcpInsertRuntimeSupport.java"),
          CLIENT_PUT_SOURCE,
          CLIENT_PUT_DIR_SOURCE,
          CLIENT_PUT_PREPARED_DATA_FACTORY_SOURCE,
          ADAPTER_FCP_MAIN_JAVA.resolve("ClientPutPutterFactory.java"),
          ADAPTER_FCP_MAIN_JAVA.resolve("ClientPutMessage.java"),
          ADAPTER_FCP_MAIN_JAVA.resolve("ClientPutDirMessage.java"),
          PERSISTENT_PUT_DIR_SOURCE,
          ADAPTER_FCP_MAIN_JAVA.resolve("SubscribeUSK.java"),
          ADAPTER_FCP_MAIN_JAVA.resolve("FCPConnectionHandler.java"));
  private static final Set<Path> DETACHED_COMPATIBILITY_SOURCES =
      Set.of(
          CLIENT_GET_SOURCE,
          CLIENT_GET_EVENT_HANDLING_SOURCE,
          CLIENT_GET_GETTER_FACTORY_SOURCE,
          CLIENT_GET_MESSAGE_REPLAY_SOURCE,
          CLIENT_GET_PERSISTENCE_CODEC_SOURCE,
          CLIENT_GET_RESTART_COORDINATOR_SOURCE,
          CLIENT_GET_STATE_SOURCE,
          CLIENT_GET_STATUS_REPORTER_SOURCE,
          CLIENT_GET_STATUS_SNAPSHOT_SOURCE,
          COMPATIBILITY_MODE_SOURCE,
          FCP_COMPATIBILITY_MODE_SOURCE,
          FCP_COMPATIBILITY_ANALYSIS_SOURCE,
          FCP_INSERT_CONTEXT_HANDLE_SOURCE,
          DEFAULT_FCP_INSERT_CONTEXT_HANDLE_SOURCE,
          DOWNLOAD_CONTEXT_SNAPSHOT_SOURCE,
          DOWNLOAD_REQUEST_STATUS_SOURCE,
          DOWNLOAD_REQUEST_STATUS_DETAILS_SOURCE,
          REQUEST_STATUS_CACHE_SOURCE);
  private static final Set<Path> FILE_UTIL_DETACHMENT_SOURCES =
      Set.of(
          ADAPTER_FCP_MAIN_JAVA.resolve("DataCarryingMessage.java"),
          ADAPTER_FCP_MAIN_JAVA.resolve("DdaAccessController.java"),
          ADAPTER_FCP_MAIN_JAVA.resolve("ClientGetMessage.java"),
          ADAPTER_FCP_MAIN_JAVA.resolve("UnsupportedPluginMessage.java"),
          ADAPTER_FCP_MAIN_JAVA.resolve("TestDdaCompleteMessage.java"));
  private static final Path BRIDGE_FCP_RUNTIME_MAIN_JAVA =
      Path.of(
          "bridge-fcp-runtime",
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "clients",
          "fcp",
          "bridge");
  private static final Path OWNERSHIP_METADATA =
      Path.of(MODULE_NAME, "gradle", "owned-output-patterns.txt");
  private static final Path BRIDGE_OWNERSHIP_METADATA =
      Path.of("bridge-fcp-runtime", "gradle", "owned-output-patterns.txt");
  private static final Path KERNEL_CONTENT_OWNERSHIP_METADATA =
      Path.of("kernel-content", "gradle", "owned-output-patterns.txt");
  private static final Path RUNTIME_NODE_OWNERSHIP_METADATA =
      Path.of("runtime-node", "gradle", "owned-output-patterns.txt");
  private static final Path DEFAULT_BRIDGE_FACTORIES =
      Path.of(
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "runtime",
          "bootstrap",
          "DefaultNodeRuntimeBridgeFactories.java");
  private static final Path ADD_REF =
      Path.of("src", "main", "java", "network", "crypta", "tools", "AddRef.java");
  private static final Pattern FCP_IMPORT_PATTERN =
      Pattern.compile("^import(?:\\s+static)?\\s+(network\\.crypta\\.clients\\.fcp\\.[^;]+);$");
  private static final Pattern FORBIDDEN_RUNTIME_NODE_IMPORT_PATTERN =
      Pattern.compile(
          "^import\\s+(network\\.crypta\\.node\\.(?:PeerNode|DarknetPeerNode)|"
              + "network\\.crypta\\.node\\.probe\\.[^;]+);$");
  private static final Set<String> FORBIDDEN_GET_RUNTIME_IMPORTS =
      Set.of(
          "network.crypta.client.FetchContext",
          "network.crypta.client.async.ClientContext",
          "network.crypta.client.async.ClientGetter",
          "network.crypta.client.async.ClientGetterRequest");
  private static final Set<String> FORBIDDEN_INSERT_RUNTIME_IMPORTS =
      Set.of(
          "network.crypta.client.HighLevelSimpleClientImpl",
          "network.crypta.client.async.ClientContext",
          "network.crypta.client.async.ClientPutter",
          "network.crypta.client.async.ClientPutterOptions",
          "network.crypta.client.async.ClientPutterRequest",
          "network.crypta.client.async.ContainerInserter",
          "network.crypta.client.async.DefaultManifestPutter",
          "network.crypta.client.async.InsertRequestParams",
          "network.crypta.client.async.ManifestPutter",
          "network.crypta.client.async.ManifestPutterParams",
          "network.crypta.client.async.USKCallback",
          "network.crypta.client.async.USKFoundEdition",
          "network.crypta.client.async.USKManager",
          "network.crypta.client.async.USKProgressCallback");
  private static final Set<String> FORBIDDEN_RUNTIME_TYPE_REFERENCES =
      Set.of("BaseClientPutter", "ClientContext", "ClientPutCallback");
  private static final Set<String> FORBIDDEN_REQUESTER_IMPORTS =
      Set.of("network.crypta.client.async.ClientRequester");
  private static final Set<String> FORBIDDEN_SERVER_INFRA_RUNTIME_TYPES =
      Set.of(
          "network.crypta.client.async.ClientContext",
          "network.crypta.client.async.PersistentJob",
          "network.crypta.client.async.DownloadCache");
  private static final Set<String> FORBIDDEN_FILTER_RUNTIME_IMPORTS =
      Set.of(
          "network.crypta.client.async.ClientContext",
          "network.crypta.client.filter.ContentFilter",
          "network.crypta.client.filter.ContentFilterCallbacks",
          "network.crypta.client.filter.ContentFilterRequest");
  private static final Set<Path> GET_RUNTIME_SEAM_SOURCES =
      Set.of(
          FCP_FETCH_RUNTIME_SUPPORT_SOURCE,
          CLIENT_GET_SOURCE,
          CLIENT_GET_FACTORY_SOURCE,
          CLIENT_GET_GETTER_FACTORY_SOURCE,
          CLIENT_GET_PERSISTENCE_CODEC_SOURCE,
          CLIENT_GET_PERSISTENCE_IO_SOURCE,
          CLIENT_GET_RESTART_COORDINATOR_SOURCE,
          CLIENT_GET_LIFECYCLE_SOURCE,
          CLIENT_GET_RETURN_PLANNER_SOURCE,
          CLIENT_GET_SETUP_SOURCE,
          CLIENT_GET_STATUS_BUILDER_SOURCE,
          DOWNLOAD_CONTEXT_SNAPSHOT_SOURCE);
  private static final Set<String> EXPECTED_DEFAULT_BRIDGE_FACTORIES_IMPORTS =
      Set.of(
          "network.crypta.clients.fcp.bridge.FcpPersistentRequestServices",
          "network.crypta.clients.fcp.bridge.FcpQueuePorts");
  private static final Set<String> EXPECTED_ADD_REF_IMPORTS =
      Set.of(
          "network.crypta.clients.fcp.AddPeer",
          "network.crypta.clients.fcp.FCPMessage",
          "network.crypta.clients.fcp.FCPServer",
          "network.crypta.clients.fcp.MessageInvalidException",
          "network.crypta.clients.fcp.NodeHelloMessage");
  private static final Set<String> FORBIDDEN_PERSISTENT_TEMP_BUCKET_IMPORTS =
      Set.of("network.crypta.support.io.PersistentTempBucketFactory");
  private static final Set<Path> FORBIDDEN_METADATA_CLUSTER_SOURCES =
      Set.of(
          CLIENT_PUT_COMPLEX_DIR_MESSAGE_SOURCE,
          CLIENT_PUT_DIR_SOURCE,
          CLIENT_PUT_PREPARED_DATA_FACTORY_SOURCE);
  private static final Set<String> FORBIDDEN_METADATA_CLUSTER_IMPORTS =
      Set.of("network.crypta.client.Metadata");
  private static final Set<String> FORBIDDEN_PERSISTENT_PUT_DIR_RUNTIME_IMPORTS =
      Set.of(
          "network.crypta.client.async.BaseManifestPutter",
          "network.crypta.support.io.DelayedFreeBucket",
          "network.crypta.support.io.DelayedFreeRandomAccessBucket",
          "network.crypta.support.io.PaddedEphemerallyEncryptedBucket",
          "network.crypta.support.io.TempBucketFactory");

  @Test
  void mainSourceLayout_whenCheckingFcpOwnership_expectLeafOwnsPackageTree() throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isDirectory(repoRoot.resolve(ADAPTER_FCP_MAIN_JAVA)),
        "adapter-fcp must own network/crypta/clients/fcp main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_FCP_MAIN_JAVA)),
        "Root project must not re-own network/crypta/clients/fcp main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_FCP_BRIDGE_MAIN_JAVA)),
        "Root project must not re-own network/crypta/clients/fcp/bridge main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ADAPTER_FCP_BRIDGE_MAIN_JAVA)),
        ":adapter-fcp must not own network/crypta/clients/fcp/bridge main sources");
  }

  @Test
  void buildWiring_whenCheckingLeafMetadata_expectOwnedOutputPatternDeclared() throws IOException {
    Path repoRoot = repoRoot();
    String settings = Files.readString(repoRoot.resolve("settings.gradle.kts"));
    String build = Files.readString(repoRoot.resolve("build.gradle.kts"));
    String adapterBuild = Files.readString(repoRoot.resolve(ADAPTER_BUILD_FILE));
    String bridgeBuild = Files.readString(repoRoot.resolve(BRIDGE_BUILD_FILE));
    Set<String> metadataPatterns = readOwnershipPatterns(repoRoot.resolve(OWNERSHIP_METADATA));
    Set<String> bridgeMetadataPatterns =
        readOwnershipPatterns(repoRoot.resolve(BRIDGE_OWNERSHIP_METADATA));
    Set<String> kernelContentPatterns =
        readOwnershipPatterns(repoRoot.resolve(KERNEL_CONTENT_OWNERSHIP_METADATA));
    Set<String> runtimeNodePatterns =
        readOwnershipPatterns(repoRoot.resolve(RUNTIME_NODE_OWNERSHIP_METADATA));

    assertTrue(settings.contains("\":adapter-fcp\""));
    assertTrue(settings.contains("\":bridge-fcp-runtime\""));
    assertTrue(build.contains("project(\":adapter-fcp\")"));
    assertTrue(build.contains("project(\":bridge-fcp-runtime\")"));
    assertFalse(
        containsDirectProjectDependency(adapterBuild, ":runtime-node"),
        ":adapter-fcp must not depend on :runtime-node");
    assertTrue(
        containsDirectProjectDependency(bridgeBuild, ":adapter-fcp"),
        ":bridge-fcp-runtime must depend on :adapter-fcp");
    assertTrue(
        containsDirectProjectDependency(bridgeBuild, ":runtime-node"),
        ":bridge-fcp-runtime must remain the concrete runtime-binding owner for FCP");
    assertTrue(metadataPatterns.contains("network/crypta/clients/fcp/*"));
    assertFalse(
        metadataPatterns.contains("network/crypta/clients/fcp/bridge/**"),
        ":adapter-fcp must not claim network/crypta/clients/fcp/bridge/** in ownership metadata");
    assertTrue(
        bridgeMetadataPatterns.contains("network/crypta/clients/fcp/bridge/**"),
        ":bridge-fcp-runtime must own network/crypta/clients/fcp/bridge/**");
    assertTrue(Files.isRegularFile(repoRoot.resolve(FCP_COMPATIBILITY_MODE_SOURCE)));
    assertTrue(Files.isRegularFile(repoRoot.resolve(FCP_COMPATIBILITY_ANALYSIS_SOURCE)));
    assertTrue(Files.isRegularFile(repoRoot.resolve(FCP_INSERT_CONTEXT_HANDLE_SOURCE)));
    assertTrue(Files.isRegularFile(repoRoot.resolve(DEFAULT_FCP_INSERT_CONTEXT_HANDLE_SOURCE)));
    assertTrue(
        kernelContentPatterns.contains(
            "network/crypta/client/events/SplitfileCompatibilityMode.class"));
    assertTrue(
        kernelContentPatterns.contains(
            "network/crypta/client/events/SplitfileCompatibilityModeEvent.class"));
    assertTrue(kernelContentPatterns.contains("network/crypta/client/events/package-info*"));
    assertFalse(
        runtimeNodePatterns.contains(
            "network/crypta/client/events/SplitfileCompatibilityModeEvent.class"));
    assertFalse(runtimeNodePatterns.contains("network/crypta/client/events/package-info*"));
  }

  @Test
  void mainSources_whenScanningFcpImports_expectOnlyBootstrapAndToolBindingSitesOutsideAdapter()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();
    Set<String> bootstrapImports = readFcpImports(repoRoot.resolve(DEFAULT_BRIDGE_FACTORIES));
    Set<String> addRefImports = readFcpImports(repoRoot.resolve(ADD_REF));

    for (Path sourceFile : findMainJavaSources(repoRoot)) {
      Path relativePath = repoRoot.relativize(sourceFile);
      if (relativePath.equals(DEFAULT_BRIDGE_FACTORIES) || relativePath.equals(ADD_REF)) {
        continue;
      }

      Set<String> imports = readFcpImports(sourceFile);
      boolean allowedMainSource =
          relativePath.startsWith(ADAPTER_FCP_MAIN_JAVA)
              || relativePath.startsWith(BRIDGE_FCP_RUNTIME_MAIN_JAVA);
      if (!imports.isEmpty() && !allowedMainSource) {
        violations.add(relativePath + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Only :adapter-fcp and :bridge-fcp-runtime main sources may import "
            + "network.crypta.clients.fcp.*, except the bootstrap binding site and the AddRef "
            + "tool."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
    assertEquals(
        EXPECTED_DEFAULT_BRIDGE_FACTORIES_IMPORTS,
        bootstrapImports,
        "DefaultNodeRuntimeBridgeFactories must be the only bootstrap-owned FCP binding " + "site");
    assertEquals(
        EXPECTED_ADD_REF_IMPORTS,
        addRefImports,
        "AddRef must be the only tool-owned FCP exception");
  }

  @Test
  void adapterFcpMain_whenScanningFileUtilImports_expectNoRuntimeFileUtilLeak() throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path source : FILE_UTIL_DETACHMENT_SOURCES) {
      Set<String> imports = readImports(repoRoot.resolve(source));
      if (imports.contains("network.crypta.support.io.FileUtil")) {
        violations.add(source + " -> network.crypta.support.io.FileUtil");
      }
    }

    for (Path sourceFile : findJavaSources(repoRoot.resolve(ADAPTER_FCP_MAIN_JAVA))) {
      if (FILE_UTIL_DETACHMENT_SOURCES.contains(repoRoot.relativize(sourceFile))) {
        continue;
      }
      Set<String> imports = readImports(sourceFile);
      if (imports.contains("network.crypta.support.io.FileUtil")) {
        violations.add(repoRoot.relativize(sourceFile) + " -> network.crypta.support.io.FileUtil");
      }
    }

    assertTrue(
        violations.isEmpty(),
        ":adapter-fcp main sources must not import network.crypta.support.io.FileUtil."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void adapterFcpMain_whenScanningProductionPackages_expectPackageInfoInEveryPackage()
      throws IOException {
    Path repoRoot = repoRoot();
    Path adapterFcpMain = repoRoot.resolve(Path.of(MODULE_NAME, "src", "main", "java"));
    Set<Path> productionPackages = new TreeSet<>(Comparator.comparing(Path::toString));
    List<String> missingPackageInfos = new ArrayList<>();

    assertTrue(Files.isDirectory(adapterFcpMain), ":adapter-fcp main Java tree must exist");

    for (Path sourceFile : findJavaSources(adapterFcpMain)) {
      String fileName = fileNameOrThrow(sourceFile);
      if (fileName.equals("package-info.java") || fileName.equals("module-info.java")) {
        continue;
      }
      productionPackages.add(parentOrThrow(sourceFile));
    }

    for (Path packagePath : productionPackages) {
      if (!Files.isRegularFile(packagePath.resolve("package-info.java"))) {
        missingPackageInfos.add(repoRoot.relativize(packagePath).toString());
      }
    }

    assertTrue(
        missingPackageInfos.isEmpty(),
        "Every :adapter-fcp main package with production Java files must declare package-info.java."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), missingPackageInfos));
  }

  @Test
  void detachedCompatibilitySources_whenScanningImports_expectNoLiveRuntimeCompatibilityTypes()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path sourceFile : DETACHED_COMPATIBILITY_SOURCES) {
      String source = Files.readString(repoRoot.resolve(sourceFile));
      if (source.contains("import network.crypta.client.async.CompatibilityAnalyser;")) {
        violations.add(sourceFile + " imports CompatibilityAnalyser");
      }
      if (source.contains("import network.crypta.client.InsertContext.CompatibilityMode;")) {
        violations.add(sourceFile + " imports InsertContext.CompatibilityMode");
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Detached compatibility sources must not import live runtime compatibility types."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void adapterFcpMain_whenScanningForbiddenRuntimeImports_expectNoPeerOrProbeLeaks()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();
    Path adapterFcpMain = repoRoot.resolve(ADAPTER_FCP_MAIN_JAVA);

    for (Path sourceFile : findJavaSources(adapterFcpMain)) {
      try (Stream<String> lines = Files.lines(sourceFile)) {
        List<String> forbiddenImports =
            lines
                .map(String::trim)
                .map(FORBIDDEN_RUNTIME_NODE_IMPORT_PATTERN::matcher)
                .filter(Matcher::matches)
                .map(matcher -> matcher.group(1))
                .toList();
        if (!forbiddenImports.isEmpty()) {
          violations.add(
              repoRoot.relativize(sourceFile) + " -> " + String.join(", ", forbiddenImports));
        }
      }
    }

    assertTrue(
        violations.isEmpty(),
        ":adapter-fcp main sources must not import PeerNode, DarknetPeerNode, or node.probe.*"
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void adapterFcpMain_whenCheckingAddPeerSeam_expectNoRuntimeClientFetchOrLoaderLeak()
      throws IOException {
    Path repoRoot = repoRoot();
    String addPeerSource = Files.readString(repoRoot.resolve(ADD_PEER_SOURCE));
    String messageRuntimeSupportSource =
        Files.readString(repoRoot.resolve(FCP_MESSAGE_RUNTIME_SUPPORT_SOURCE));

    assertFalse(
        addPeerSource.contains("import network.crypta.client.HighLevelSimpleClient;"),
        "AddPeer must not import HighLevelSimpleClient directly");
    assertFalse(
        addPeerSource.contains("import network.crypta.client.FetchException;"),
        "AddPeer must not import FetchException directly");
    assertFalse(
        addPeerSource.contains(
            "import network.crypta.runtime.peers.reference.PeerReferenceTextLoader;"),
        "AddPeer must not import PeerReferenceTextLoader directly");
    assertFalse(
        messageRuntimeSupportSource.contains(" makeClient("),
        "FcpMessageRuntimeSupport must not expose raw makeClient(...) anymore");
  }

  @Test
  void adapterFcpMain_whenCheckingPersistentBucketSeam_expectNoLegacyTempFactoryImports()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path source :
        Set.of(
            FCP_MESSAGE_SOURCE,
            CLIENT_PUT_COMPLEX_DIR_MESSAGE_SOURCE,
            FCP_CONNECTION_INPUT_HANDLER_SOURCE,
            FCP_SERVER_RUNTIME_SUPPORT_SOURCE,
            FCP_SERVER_DEPENDENCIES_SOURCE)) {
      Set<String> imports = readImports(repoRoot.resolve(source));
      Set<String> forbiddenImports = new TreeSet<>(imports);
      forbiddenImports.retainAll(FORBIDDEN_PERSISTENT_TEMP_BUCKET_IMPORTS);
      if (!forbiddenImports.isEmpty()) {
        violations.add(source + " -> " + String.join(", ", forbiddenImports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Persistent bucket adapter sources must not import PersistentTempBucketFactory."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void adapterFcpMain_whenCheckingMetadataBoundary_expectNoRuntimeMetadataImports()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path source : FORBIDDEN_METADATA_CLUSTER_SOURCES) {
      Set<String> imports = readImports(repoRoot.resolve(source));
      Set<String> forbiddenImports = new TreeSet<>(imports);
      forbiddenImports.retainAll(FORBIDDEN_METADATA_CLUSTER_IMPORTS);
      if (!forbiddenImports.isEmpty()) {
        violations.add(source + " -> " + String.join(", ", forbiddenImports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Metadata boundary adapter sources must not import runtime-owned Metadata."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void adapterFcpMain_whenCheckingPersistentPutDirBoundary_expectNoRuntimeManifestHelpers()
      throws IOException {
    Path repoRoot = repoRoot();
    Set<String> imports = readImports(repoRoot.resolve(PERSISTENT_PUT_DIR_SOURCE));
    Set<String> forbiddenImports = new TreeSet<>(imports);
    forbiddenImports.retainAll(FORBIDDEN_PERSISTENT_PUT_DIR_RUNTIME_IMPORTS);

    assertTrue(
        forbiddenImports.isEmpty(),
        "PersistentPutDir must not import runtime-owned manifest helpers or bucket wrappers."
            + System.lineSeparator()
            + PERSISTENT_PUT_DIR_SOURCE
            + " -> "
            + String.join(", ", forbiddenImports));
  }

  @Test
  void adapterFcpMain_whenCheckingFilterSeam_expectNoLegacyRuntimeFilterImports()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path source :
        Set.of(
            FILTER_MESSAGE_SOURCE,
            FCP_MESSAGE_RUNTIME_SUPPORT_SOURCE,
            FCP_SERVER_SOURCE,
            FCP_SERVER_DEPENDENCIES_SOURCE)) {
      Set<String> imports = readImports(repoRoot.resolve(source));
      Set<String> forbiddenImports = new TreeSet<>(imports);
      forbiddenImports.retainAll(FORBIDDEN_FILTER_RUNTIME_IMPORTS);
      if (!forbiddenImports.isEmpty()) {
        violations.add(source + " -> " + String.join(", ", forbiddenImports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Filter adapter sources must not import ClientContext, ContentFilter, "
            + "ContentFilterCallbacks, or ContentFilterRequest."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void
      adapterFcpMain_whenCheckingLegacyRuntimeTypeBoundary_expectNoClientContextOrInsertCallbackReferences()
          throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path sourceFile : findJavaSources(repoRoot.resolve(ADAPTER_FCP_MAIN_JAVA))) {
      Path relativePath = repoRoot.relativize(sourceFile);
      String source = Files.readString(sourceFile);
      Set<String> forbiddenReferences = new TreeSet<>();
      for (String forbiddenReference : FORBIDDEN_RUNTIME_TYPE_REFERENCES) {
        if (source.contains(forbiddenReference)) {
          forbiddenReferences.add(forbiddenReference);
        }
      }
      if (!forbiddenReferences.isEmpty()) {
        violations.add(relativePath + " -> " + String.join(", ", forbiddenReferences));
      }
    }

    assertTrue(
        violations.isEmpty(),
        ":adapter-fcp main sources must not reference ClientContext, BaseClientPutter, or "
            + "ClientPutCallback."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void adapterFcpMain_whenCheckingGetRuntimeSeam_expectNoLiveFetchTypeImports() throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path source : GET_RUNTIME_SEAM_SOURCES) {
      Set<String> imports = readImports(repoRoot.resolve(source));
      Set<String> forbiddenImports = new TreeSet<>(imports);
      forbiddenImports.retainAll(FORBIDDEN_GET_RUNTIME_IMPORTS);
      if (!forbiddenImports.isEmpty()) {
        violations.add(source + " -> " + String.join(", ", forbiddenImports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "GET-path adapter sources must not import live runtime fetch types."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void fetchRuntimeSupport_whenCheckingPublicSurface_expectNoLegacyLiveFetchAccessors()
      throws IOException {
    Path repoRoot = repoRoot();
    String source = Files.readString(repoRoot.resolve(FCP_FETCH_RUNTIME_SUPPORT_SOURCE));

    assertFalse(source.contains("clientContext("));
    assertFalse(source.contains("defaultPersistentFetchContext("));
    assertFalse(source.contains("FetchContext"));
    assertFalse(source.contains("ClientContext"));
  }

  @Test
  void getCallSites_whenCheckingMixedFiles_expectNoLegacyFetchRuntimeReachThrough()
      throws IOException {
    Path repoRoot = repoRoot();
    String connectionHandler = Files.readString(repoRoot.resolve(FCP_CONNECTION_HANDLER_SOURCE));
    String persistentOps = Files.readString(repoRoot.resolve(FCP_SERVER_PERSISTENT_OPS_SOURCE));

    assertFalse(connectionHandler.contains("fetchRuntimeSupport().clientContext()"));
    assertFalse(connectionHandler.contains("messageFetchRuntimeSupport().clientContext()"));
    assertFalse(connectionHandler.contains("defaultPersistentFetchContext("));
    assertFalse(persistentOps.contains("fetchRuntimeSupport.clientContext()"));
    assertFalse(persistentOps.contains("defaultPersistentFetchContext("));
  }

  @Test
  void adapterFcpMain_whenCheckingInsertFamilySeam_expectNoLiveInsertRuntimeImports()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path source : INSERT_FAMILY_SEAM_SOURCES) {
      Set<String> imports = readImports(repoRoot.resolve(source));
      Set<String> forbiddenImports = new TreeSet<>(imports);
      forbiddenImports.retainAll(FORBIDDEN_INSERT_RUNTIME_IMPORTS);
      if (!forbiddenImports.isEmpty()) {
        violations.add(source + " -> " + String.join(", ", forbiddenImports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Insert-family adapter sources must not import live runtime insert execution types."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void adapterFcpMain_whenScanningRequesterImports_expectNoLiveClientRequesterLeak()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();
    Path adapterFcpMain = repoRoot.resolve(ADAPTER_FCP_MAIN_JAVA);

    for (Path sourceFile : findJavaSources(adapterFcpMain)) {
      Set<String> imports = readImports(sourceFile);
      Set<String> forbiddenImports = new TreeSet<>(imports);
      forbiddenImports.retainAll(FORBIDDEN_REQUESTER_IMPORTS);
      if (!forbiddenImports.isEmpty()) {
        violations.add(
            repoRoot.relativize(sourceFile) + " -> " + String.join(", ", forbiddenImports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        ":adapter-fcp main sources must not import ClientRequester."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void serverInfrastructure_whenCheckingDetachedRuntimeSeams_expectNoLiveRuntimeInfraLeaks()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();
    String serverSource = Files.readString(repoRoot.resolve(FCP_SERVER_SOURCE));
    String persistentOpsSource =
        Files.readString(repoRoot.resolve(FCP_SERVER_PERSISTENT_OPS_SOURCE));
    String connectionHandlerSource =
        Files.readString(repoRoot.resolve(FCP_CONNECTION_HANDLER_SOURCE));
    String persistentRequestClientSource =
        Files.readString(repoRoot.resolve(PERSISTENT_REQUEST_CLIENT_SOURCE));
    String clientRequestSource = Files.readString(repoRoot.resolve(CLIENT_REQUEST_SOURCE));
    String runtimeSupportSource =
        Files.readString(repoRoot.resolve(FCP_SERVER_RUNTIME_SUPPORT_SOURCE));

    collectForbiddenRuntimeInfraImportViolations(violations, FCP_SERVER_SOURCE, repoRoot);
    collectForbiddenRuntimeInfraImportViolations(
        violations, FCP_SERVER_PERSISTENT_OPS_SOURCE, repoRoot);
    collectForbiddenRuntimeInfraImportViolations(
        violations, FCP_CONNECTION_HANDLER_SOURCE, repoRoot);
    collectForbiddenRuntimeInfraImportViolations(
        violations, PERSISTENT_REQUEST_CLIENT_SOURCE, repoRoot);

    requireAbsent(
        violations,
        FCP_SERVER_SOURCE,
        serverSource,
        "implements Runnable, DownloadCache",
        "must not implement runtime-owned DownloadCache");
    requireAbsent(
        violations,
        FCP_SERVER_SOURCE,
        serverSource,
        "lookup(\n      FreenetURI key, boolean noFilter, ClientContext context",
        "must not expose cache lookup with live ClientContext");

    requireAbsent(
        violations,
        FCP_SERVER_PERSISTENT_OPS_SOURCE,
        persistentOpsSource,
        "new PersistentJob()",
        "must not allocate runtime-owned PersistentJob directly");
    requireAbsent(
        violations,
        FCP_SERVER_PERSISTENT_OPS_SOURCE,
        persistentOpsSource,
        "run(ClientContext context)",
        "must not declare queued work against live ClientContext");
    requireAbsent(
        violations,
        FCP_SERVER_PERSISTENT_OPS_SOURCE,
        persistentOpsSource,
        "req.restart(clientContext(),",
        "must use detached restart wrapper");
    requireAbsent(
        violations,
        FCP_SERVER_PERSISTENT_OPS_SOURCE,
        persistentOpsSource,
        "clientContext().jobRunner.queue(",
        "must queue through the detached server runtime seam");
    requireAbsent(
        violations,
        FCP_SERVER_PERSISTENT_OPS_SOURCE,
        persistentOpsSource,
        "lookup(\n      FreenetURI key, boolean noFilter, ClientContext context",
        "must not expose cache lookup with live ClientContext");
    requireAbsent(
        violations,
        FCP_SERVER_PERSISTENT_OPS_SOURCE,
        persistentOpsSource,
        "private ClientContext clientContext()",
        "must not keep a live ClientContext helper");
    requirePresent(
        violations,
        FCP_SERVER_PERSISTENT_OPS_SOURCE,
        persistentOpsSource,
        "implements FcpDownloadCache",
        "must implement the detached FcpDownloadCache seam");
    requirePresent(
        violations,
        FCP_SERVER_PERSISTENT_OPS_SOURCE,
        persistentOpsSource,
        "runtimeSupport.queuePersistentJob(",
        "must queue persistent work through the detached runtime seam");

    requireAbsent(
        violations,
        FCP_CONNECTION_HANDLER_SOURCE,
        connectionHandlerSource,
        "new PersistentJob()",
        "must not allocate runtime-owned PersistentJob directly");
    requireAbsent(
        violations,
        FCP_CONNECTION_HANDLER_SOURCE,
        connectionHandlerSource,
        "serverRuntimeSupport().clientContext()",
        "must not reach through to live ClientContext for server infrastructure");
    requireAbsent(
        violations,
        FCP_CONNECTION_HANDLER_SOURCE,
        connectionHandlerSource,
        "private ClientContext serverClientContext()",
        "must not keep a live ClientContext helper");
    requirePresent(
        violations,
        FCP_CONNECTION_HANDLER_SOURCE,
        connectionHandlerSource,
        "private void queuePersistentJob(FcpPersistentJob job",
        "must queue detached FcpPersistentJob work");

    requireAbsent(
        violations,
        PERSISTENT_REQUEST_CLIENT_SOURCE,
        persistentRequestClientSource,
        "removeByIdentifier(\n"
            + "      String identifier, boolean kill, FCPServer server, ClientContext context)",
        "must not require live ClientContext in removeByIdentifier");
    requirePresent(
        violations,
        PERSISTENT_REQUEST_CLIENT_SOURCE,
        persistentRequestClientSource,
        "PersistentRequestRuntimeContext context",
        "must use detached PersistentRequestRuntimeContext");

    requirePresent(
        violations,
        CLIENT_REQUEST_SOURCE,
        clientRequestSource,
        "public abstract boolean restart(",
        "must expose detached restart signature");
    requireAbsent(
        violations,
        CLIENT_REQUEST_SOURCE,
        clientRequestSource,
        "restart(runtimeSupport.clientContext(), disableFilterData)",
        "must not restart through live ClientContext reach-through");
    requirePresent(
        violations,
        CLIENT_REQUEST_SOURCE,
        clientRequestSource,
        "runtimeSupport.queuePersistentJob(",
        "must queue restart work through the detached runtime seam");

    requirePresent(
        violations,
        FCP_SERVER_RUNTIME_SUPPORT_SOURCE,
        runtimeSupportSource,
        "PersistentRequestRuntimeContext persistentRequestRuntimeContext();",
        "must expose detached runtime context");
    requirePresent(
        violations,
        FCP_SERVER_RUNTIME_SUPPORT_SOURCE,
        runtimeSupportSource,
        "void queuePersistentJob(FcpPersistentJob job, int priority)",
        "must expose detached persistent job queueing");
    requirePresent(
        violations,
        FCP_SERVER_RUNTIME_SUPPORT_SOURCE,
        runtimeSupportSource,
        "void setCheckpointASAP();",
        "must expose detached checkpoint signaling");
    requireAbsent(
        violations,
        FCP_SERVER_RUNTIME_SUPPORT_SOURCE,
        runtimeSupportSource,
        "ClientContext",
        "must not expose live ClientContext");

    assertTrue(
        violations.isEmpty(),
        "Server/runtime infrastructure sources must use detached adapter-owned seams only."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .filter(AdapterFcpBoundaryTest::isTrackedJavaSource)
          .sorted(Comparator.comparing(Path::toString))
          .toList();
    }
  }

  private static List<Path> findMainJavaSources(Path repoRoot) throws IOException {
    try (Stream<Path> walk = Files.walk(repoRoot)) {
      return walk.filter(Files::isRegularFile)
          .filter(AdapterFcpBoundaryTest::isTrackedJavaSource)
          .filter(path -> isMainJavaSource(repoRoot.relativize(path)))
          .sorted(Comparator.comparing(path -> repoRoot.relativize(path).toString()))
          .toList();
    }
  }

  private static boolean isTrackedJavaSource(Path path) {
    String fileName = fileNameOrThrow(path);
    return fileName.endsWith(".java") && !fileName.startsWith("._");
  }

  private static boolean isMainJavaSource(Path relativePath) {
    String normalized = relativePath.toString().replace(File.separatorChar, '/');
    return !normalized.startsWith("build/")
        && !normalized.contains("/build/")
        && !normalized.startsWith(".gradle/")
        && !normalized.contains("/.gradle/")
        && !normalized.startsWith(".git/")
        && !normalized.contains("/.git/")
        && (normalized.startsWith("src/main/java/") || normalized.contains("/src/main/java/"));
  }

  private static Set<String> readFcpImports(Path file) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .map(FCP_IMPORT_PATTERN::matcher)
          .filter(Matcher::matches)
          .map(matcher -> matcher.group(1))
          .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    }
  }

  private static Set<String> readImports(Path file) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .filter(line -> line.startsWith("import "))
          .map(line -> line.substring("import ".length(), line.length() - 1))
          .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    }
  }

  private static Set<String> readOwnershipPatterns(Path file) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .filter(line -> !line.isEmpty())
          .filter(line -> !line.startsWith("#"))
          .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    }
  }

  private static boolean containsDirectProjectDependency(String buildScript, String modulePath) {
    String uncommentedScript =
        buildScript.replaceAll("(?s)/\\*.*?\\*/", "").replaceAll("(?m)//.*$", "");
    Matcher invocationMatcher = Pattern.compile("\\bproject\\s*\\(").matcher(uncommentedScript);

    while (invocationMatcher.find()) {
      int openParen = uncommentedScript.indexOf('(', invocationMatcher.start());
      int closeParen = findMatchingParenthesis(uncommentedScript, openParen);
      if (closeParen == -1) {
        continue;
      }
      String invocationArgs = uncommentedScript.substring(openParen + 1, closeParen);
      String pathExpression = extractProjectPathExpression(invocationArgs);
      if (pathExpression == null) {
        continue;
      }
      String resolvedPath =
          resolveStringExpression(
              stripEnclosingParentheses(pathExpression),
              uncommentedScript,
              new java.util.HashSet<>());
      if (modulePath.equals(resolvedPath)) {
        return true;
      }
    }
    return false;
  }

  private static String extractProjectPathExpression(String invocationArgs) {
    String trimmedArgs = stripEnclosingParentheses(invocationArgs.trim());
    if (trimmedArgs.startsWith("mapOf")) {
      int openParen = trimmedArgs.indexOf('(');
      if (openParen == -1) {
        return null;
      }
      int closeParen = findMatchingParenthesis(trimmedArgs, openParen);
      if (closeParen == -1) {
        return null;
      }
      String mapArgs = trimmedArgs.substring(openParen + 1, closeParen);
      for (String entry : splitTopLevel(mapArgs, ',')) {
        Matcher pathEntryMatcher =
            Pattern.compile("^\\s*\"path\"\\s*to\\s*(.+)$", Pattern.DOTALL).matcher(entry);
        if (pathEntryMatcher.matches()) {
          return pathEntryMatcher.group(1).trim();
        }
      }
      return null;
    }

    int equalsIndex = findTopLevelChar(trimmedArgs, '=');
    if (equalsIndex != -1) {
      String leftSide = trimmedArgs.substring(0, equalsIndex).trim();
      if (leftSide.equals("path")) {
        return trimmedArgs.substring(equalsIndex + 1).trim();
      }
    }

    return trimmedArgs;
  }

  private static String resolveStringExpression(
      String expression, String script, Set<String> visitedIdentifiers) {
    String trimmedExpression = stripEnclosingParentheses(expression.trim());
    if (trimmedExpression.isEmpty()) {
      return null;
    }

    if (trimmedExpression.startsWith("\"") && trimmedExpression.endsWith("\"")) {
      return trimmedExpression.substring(1, trimmedExpression.length() - 1);
    }

    List<String> concatenatedParts = splitTopLevel(trimmedExpression, '+');
    if (concatenatedParts.size() > 1) {
      StringBuilder resolved = new StringBuilder();
      for (String part : concatenatedParts) {
        String resolvedPart = resolveStringExpression(part, script, visitedIdentifiers);
        if (resolvedPart == null) {
          return null;
        }
        resolved.append(resolvedPart);
      }
      return resolved.toString();
    }

    if (trimmedExpression.matches("[A-Za-z_][A-Za-z0-9_]*")
        && visitedIdentifiers.add(trimmedExpression)) {
      Matcher assignmentMatcher =
          Pattern.compile(
                  "(?m)^\\s*(?:val|var)\\s+" + Pattern.quote(trimmedExpression) + "\\s*=\\s*(.+)$")
              .matcher(script);
      if (assignmentMatcher.find()) {
        return resolveStringExpression(assignmentMatcher.group(1), script, visitedIdentifiers);
      }
    }

    return null;
  }

  private static String stripEnclosingParentheses(String expression) {
    String trimmed = expression.trim();
    while (trimmed.startsWith("(")
        && trimmed.endsWith(")")
        && findMatchingParenthesis(trimmed, 0) == trimmed.length() - 1) {
      trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
    }
    return trimmed;
  }

  private static List<String> splitTopLevel(String text, char delimiter) {
    List<String> parts = new ArrayList<>();
    int segmentStart = 0;
    int depth = 0;
    boolean inString = false;
    char stringDelimiter = 0;

    for (int index = 0; index < text.length(); index++) {
      char current = text.charAt(index);
      char previous = index > 0 ? text.charAt(index - 1) : 0;

      if (inString) {
        if (current == stringDelimiter && previous != '\\') {
          inString = false;
        }
        continue;
      }

      if (current == '"' || current == '\'') {
        inString = true;
        stringDelimiter = current;
        continue;
      }

      if (current == '(') {
        depth++;
      } else if (current == ')') {
        depth--;
      } else if (current == delimiter && depth == 0) {
        parts.add(text.substring(segmentStart, index).trim());
        segmentStart = index + 1;
      }
    }

    parts.add(text.substring(segmentStart).trim());
    return parts;
  }

  private static int findTopLevelChar(String text, char target) {
    int depth = 0;
    boolean inString = false;
    char stringDelimiter = 0;

    for (int index = 0; index < text.length(); index++) {
      char current = text.charAt(index);
      char previous = index > 0 ? text.charAt(index - 1) : 0;

      if (inString) {
        if (current == stringDelimiter && previous != '\\') {
          inString = false;
        }
        continue;
      }

      if (current == '"' || current == '\'') {
        inString = true;
        stringDelimiter = current;
        continue;
      }

      if (current == '(') {
        depth++;
      } else if (current == ')') {
        depth--;
      } else if (current == target && depth == 0) {
        return index;
      }
    }

    return -1;
  }

  private static int findMatchingParenthesis(String text, int openParen) {
    int depth = 0;
    boolean inString = false;
    char stringDelimiter = 0;

    for (int index = openParen; index < text.length(); index++) {
      char current = text.charAt(index);
      char previous = index > 0 ? text.charAt(index - 1) : 0;

      if (inString) {
        if (current == stringDelimiter && previous != '\\') {
          inString = false;
        }
        continue;
      }

      if (current == '"' || current == '\'') {
        inString = true;
        stringDelimiter = current;
        continue;
      }

      if (current == '(') {
        depth++;
      } else if (current == ')') {
        depth--;
        if (depth == 0) {
          return index;
        }
      }
    }

    return -1;
  }

  private static void collectForbiddenRuntimeInfraImportViolations(
      List<String> violations, Path source, Path repoRoot) throws IOException {
    Set<String> imports = readImports(repoRoot.resolve(source));
    Set<String> forbiddenImports = new TreeSet<>(imports);
    forbiddenImports.retainAll(FORBIDDEN_SERVER_INFRA_RUNTIME_TYPES);
    if (!forbiddenImports.isEmpty()) {
      violations.add(
          source
              + " must not import live server/runtime infrastructure types: "
              + forbiddenImports);
    }
  }

  private static void requireAbsent(
      List<String> violations,
      Path source,
      String sourceText,
      String forbiddenSnippet,
      String requirement) {
    if (sourceText.contains(forbiddenSnippet)) {
      violations.add(source + " " + requirement + " [found: " + forbiddenSnippet + ']');
    }
  }

  private static void requirePresent(
      List<String> violations,
      Path source,
      String sourceText,
      String requiredSnippet,
      String requirement) {
    if (!sourceText.contains(requiredSnippet)) {
      violations.add(source + " " + requirement + " [missing: " + requiredSnippet + ']');
    }
  }

  private static Path parentOrThrow(Path path) {
    Path parent = path.getParent();
    assertNotNull(parent, "Java source path must have a parent: " + path);
    return parent;
  }

  private static String fileNameOrThrow(Path path) {
    Path fileName = path.getFileName();
    assertNotNull(fileName, "Java source path must have a file name: " + path);
    return fileName.toString();
  }

  private static Path repoRoot() throws IOException {
    Path path = Path.of("");
    Path directory = path.toAbsolutePath().normalize();
    while (directory != null && !Files.isRegularFile(directory.resolve("settings.gradle.kts"))) {
      directory = directory.getParent();
    }
    assertNotNull(directory, "Could not locate the repo root from " + path.toAbsolutePath());
    return directory.toRealPath();
  }
}
