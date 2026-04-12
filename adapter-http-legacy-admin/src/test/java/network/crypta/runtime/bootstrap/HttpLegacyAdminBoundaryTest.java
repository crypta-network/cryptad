package network.crypta.runtime.bootstrap;

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
class HttpLegacyAdminBoundaryTest {
  private static final String MODULE_NAME = "adapter-http-legacy-admin";
  private static final String BRIDGE_MODULE_NAME = "bridge-http-runtime";
  private static final Path ROOT_HTTP_MAIN_JAVA =
      Path.of("src", "main", "java", "network", "crypta", "clients", "http");
  private static final Path ROOT_HTTP_MAIN_RESOURCES =
      Path.of("src", "main", "resources", "network", "crypta", "clients", "http");
  private static final Path ADAPTER_HTTP_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "clients", "http");
  private static final Path ADAPTER_SIMPLE_TOADLET_SERVER =
      ADAPTER_HTTP_MAIN_JAVA.resolve("SimpleToadletServer.java");
  private static final Path ADAPTER_N2NTM_TOADLET =
      ADAPTER_HTTP_MAIN_JAVA.resolve("N2NTMToadlet.java");
  private static final Path ADAPTER_QUEUE_TOADLET =
      ADAPTER_HTTP_MAIN_JAVA.resolve("QueueToadlet.java");
  private static final Set<Path> CONNECTIONS_TOADLETS =
      Set.of(
          ADAPTER_HTTP_MAIN_JAVA.resolve("ConnectionsToadlet.java"),
          ADAPTER_HTTP_MAIN_JAVA.resolve("DarknetConnectionsToadlet.java"),
          ADAPTER_HTTP_MAIN_JAVA.resolve("OpennetConnectionsToadlet.java"));
  private static final Path ADAPTER_HTTP_MAIN_RESOURCES =
      Path.of(MODULE_NAME, "src", "main", "resources", "network", "crypta", "clients", "http");
  private static final Path ADAPTER_BRIDGE_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "clients", "http", "bridge");
  private static final Path ADAPTER_GEOIP_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "clients", "http", "geoip");
  private static final Path BRIDGE_HTTP_MAIN_JAVA =
      Path.of(
          BRIDGE_MODULE_NAME,
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "clients",
          "http",
          "bridge");
  private static final Path BRIDGE_GEOIP_MAIN_JAVA =
      Path.of(
          BRIDGE_MODULE_NAME,
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "clients",
          "http",
          "geoip");
  private static final Path OWNERSHIP_METADATA =
      Path.of(MODULE_NAME, "gradle", "owned-output-patterns.txt");
  private static final Path BRIDGE_OWNERSHIP_METADATA =
      Path.of(BRIDGE_MODULE_NAME, "gradle", "owned-output-patterns.txt");
  private static final Path RUNTIME_SPI_CONNECTIVITY_PAGE_PATHS =
      Path.of(
          "runtime-spi",
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "runtime",
          "http",
          "ConnectivityPagePaths.java");
  private static final Path RUNTIME_SPI_UPDATER_PATHS =
      Path.of(
          "runtime-spi",
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "runtime",
          "updater",
          "UpdaterPaths.java");
  private static final Path RUNTIME_NODE_CONNECTIVITY_PAGE_PATHS =
      Path.of(
          "runtime-node",
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "runtime",
          "http",
          "ConnectivityPagePaths.java");
  private static final Path RUNTIME_NODE_UPDATER_PATHS =
      Path.of(
          "runtime-node",
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "runtime",
          "updater",
          "UpdaterPaths.java");
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
  private static final Pattern LEGACY_HTTP_IMPORT_PATTERN =
      Pattern.compile("^import(?:\\s+static)?\\s+(network\\.crypta\\.clients\\.http\\.[^;]+);$");
  private static final Set<String> FORBIDDEN_ADAPTER_HTTP_IMPORTS =
      Set.of(
          "import network.crypta.node.PeerNodeStatus;",
          "import network.crypta.node.DarknetPeerNodeStatus;",
          "import network.crypta.node.OpennetPeerNodeStatus;",
          "import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;",
          "import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;",
          "import network.crypta.node.Version;",
          "import network.crypta.runtime.peers.html.PeerTrustInputForAddPeerBoxNode;",
          "import network.crypta.runtime.peers.html.PeerVisibilityInputForAddPeerBoxNode;");
  private static final Set<String> EXPECTED_DEFAULT_BRIDGE_FACTORIES_HTTP_IMPORTS =
      Set.of(
          "network.crypta.clients.http.bridge.CoreHttpShellRuntimeSupport",
          "network.crypta.clients.http.bridge.HttpShellContainers",
          "network.crypta.clients.http.bridge.geoip.HttpGeoIpCountryLookups",
          "network.crypta.clients.http.bridge.security.CorePasswordFormPageRenderer");

  @Test
  void mainSourceLayout_whenCheckingLegacyHttpOwnership_expectOnlyAdapterOwnsHttpTree()
      throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isDirectory(repoRoot.resolve(ADAPTER_HTTP_MAIN_JAVA)),
        "adapter-http-legacy-admin must own network/crypta/clients/http main sources");
    assertTrue(
        Files.isDirectory(repoRoot.resolve(ADAPTER_HTTP_MAIN_RESOURCES)),
        "adapter-http-legacy-admin must own network/crypta/clients/http main resources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_HTTP_MAIN_JAVA)),
        "Root project must not re-own network/crypta/clients/http main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_HTTP_MAIN_RESOURCES)),
        "Root project must not re-own network/crypta/clients/http main resources");
    assertFalse(
        hasJavaSources(repoRoot.resolve(ADAPTER_BRIDGE_MAIN_JAVA)),
        "adapter-http-legacy-admin must not own network/crypta/clients/http/bridge main sources");
    assertFalse(
        hasJavaSources(repoRoot.resolve(ADAPTER_GEOIP_MAIN_JAVA)),
        "adapter-http-legacy-admin must not own network/crypta/clients/http/geoip main sources");
    assertTrue(
        Files.isDirectory(repoRoot.resolve(BRIDGE_HTTP_MAIN_JAVA)),
        ":bridge-http-runtime must own network/crypta/clients/http/bridge main sources");
    assertTrue(
        Files.isDirectory(repoRoot.resolve(BRIDGE_GEOIP_MAIN_JAVA)),
        ":bridge-http-runtime must own network/crypta/clients/http/geoip main sources");
  }

  @Test
  void buildWiring_whenCheckingLeafMetadata_expectBridgeSplitDeclaredAndOwned() throws IOException {
    Path repoRoot = repoRoot();
    String settings = Files.readString(repoRoot.resolve("settings.gradle.kts"));
    String build = Files.readString(repoRoot.resolve("build.gradle.kts"));
    String bridgeMetadata = Files.readString(repoRoot.resolve(BRIDGE_OWNERSHIP_METADATA));
    String adapterMetadata = Files.readString(repoRoot.resolve(OWNERSHIP_METADATA));

    assertTrue(settings.contains("\":bridge-http-runtime\""));
    assertTrue(build.contains("project(\":bridge-http-runtime\")"));
    assertTrue(settings.contains("\":adapter-http-legacy-admin\""));
    assertTrue(build.contains("project(\":adapter-http-legacy-admin\")"));
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(BRIDGE_OWNERSHIP_METADATA)),
        ":bridge-http-runtime must declare owned-output-patterns.txt");
    assertTrue(bridgeMetadata.contains("network/crypta/clients/http/bridge/**"));
    assertTrue(bridgeMetadata.contains("network/crypta/clients/http/geoip/**"));
    assertFalse(
        adapterMetadata.contains("network/crypta/clients/http/bridge/**"),
        ":adapter-http-legacy-admin must not claim network/crypta/clients/http/bridge/**");
    assertFalse(
        adapterMetadata.contains("network/crypta/clients/http/geoip/**"),
        ":adapter-http-legacy-admin must not claim network/crypta/clients/http/geoip/**");
  }

  @Test
  void mainSources_whenScanningLegacyHttpImports_expectOnlyBootstrapBindingSiteOutsideAdapter()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();
    Set<String> bootstrapHttpImports =
        readLegacyHttpImports(repoRoot.resolve(DEFAULT_BRIDGE_FACTORIES));

    for (Path sourceFile : findMainJavaSources(repoRoot)) {
      Path relativePath = repoRoot.relativize(sourceFile);
      if (relativePath.equals(DEFAULT_BRIDGE_FACTORIES)) {
        continue;
      }

      Set<String> imports = readLegacyHttpImports(sourceFile);
      if (!imports.isEmpty()
          && !relativePath.startsWith(ADAPTER_HTTP_MAIN_JAVA)
          && !relativePath.startsWith(BRIDGE_HTTP_MAIN_JAVA)
          && !relativePath.startsWith(BRIDGE_GEOIP_MAIN_JAVA)) {
        violations.add(relativePath + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Only adapter-http-legacy-admin, bridge-http-runtime, and the bootstrap binding site may "
            + "import network.crypta.clients.http.*."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
    assertEquals(
        EXPECTED_DEFAULT_BRIDGE_FACTORIES_HTTP_IMPORTS,
        bootstrapHttpImports,
        "DefaultNodeRuntimeBridgeFactories must remain the narrow bootstrap-owned HTTP binding "
            + "site");
  }

  @Test
  void mainSources_whenCheckingSimpleToadletServerImports_expectHttpShellSeamsDetached()
      throws IOException {
    Path repoRoot = repoRoot();
    Path sourceFile = repoRoot.resolve(ADAPTER_SIMPLE_TOADLET_SERVER);
    String source = Files.readString(sourceFile);
    Set<String> imports = readImports(sourceFile);

    assertFalse(
        imports.contains("import network.crypta.clients.http.FProxyRegistrar;"),
        "SimpleToadletServer must not import the admin-owned FProxyRegistrar helper anymore.");
    assertFalse(
        imports.contains("import network.crypta.clients.http.FProxyRegistrarDependencies;"),
        "SimpleToadletServer must not import FProxyRegistrarDependencies anymore.");
    assertFalse(
        source.contains("FProxyRegistrar.maybeCreateFProxyEtc"),
        "SimpleToadletServer must not call FProxyRegistrar.maybeCreateFProxyEtc anymore.");
    assertFalse(
        source.contains("new FProxyRegistrarDependencies("),
        "SimpleToadletServer must not construct FProxyRegistrarDependencies anymore.");
    assertFalse(
        source.contains("FProxyFetchInProgress.REFILTER_POLICY"),
        "SimpleToadletServer must use the HTTP-local refilter policy type instead of the nested "
            + "FProxy enum.");
  }

  @Test
  void mainSources_whenScanningAdapterHttpImports_expectRemovedPeerStatusAndAddPeerImportsAbsent()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path sourceFile : findMainJavaSources(repoRoot)) {
      Path relativePath = repoRoot.relativize(sourceFile);
      if (!CONNECTIONS_TOADLETS.contains(relativePath)) {
        continue;
      }

      Set<String> imports = readImports(sourceFile);
      for (String forbiddenImport : FORBIDDEN_ADAPTER_HTTP_IMPORTS) {
        if (imports.contains(forbiddenImport)) {
          violations.add(relativePath + " -> " + forbiddenImport);
        }
      }
    }

    assertTrue(
        violations.isEmpty(),
        "adapter-http-legacy-admin main sources must not import the peer-status, darknet enum, or "
            + "runtime add-peer helper types removed in PR-158."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void
      mainSources_whenScanningAdapterHttpImports_expectRemovedLifecycleAndQueueHelperImportsAbsent()
          throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path sourceFile : List.of(ADAPTER_N2NTM_TOADLET, ADAPTER_QUEUE_TOADLET)) {
      Set<String> imports = readImports(repoRoot.resolve(sourceFile));
      for (String forbiddenImport : forbiddenAdapterHttpImports(sourceFile)) {
        if (imports.contains(forbiddenImport)) {
          violations.add(sourceFile + " -> " + forbiddenImport);
        }
      }
    }

    assertTrue(
        violations.isEmpty(),
        "adapter-http-legacy-admin main sources must not import NodeStarter or the queue progress "
            + "cell helper classes removed in PR-159."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void mainSourceLayout_whenCheckingRuntimeSpiOwnership_expectMovedPathHelpersLiveInRuntimeSpi()
      throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isRegularFile(repoRoot.resolve(RUNTIME_SPI_CONNECTIVITY_PAGE_PATHS)),
        "ConnectivityPagePaths.java must live under runtime-spi");
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(RUNTIME_SPI_UPDATER_PATHS)),
        "UpdaterPaths.java must live under runtime-spi");
    assertFalse(
        Files.exists(repoRoot.resolve(RUNTIME_NODE_CONNECTIVITY_PAGE_PATHS)),
        "ConnectivityPagePaths.java must not remain under runtime-node");
    assertFalse(
        Files.exists(repoRoot.resolve(RUNTIME_NODE_UPDATER_PATHS)),
        "UpdaterPaths.java must not remain under runtime-node");
  }

  private static List<Path> findMainJavaSources(Path repoRoot) throws IOException {
    try (Stream<Path> walk = Files.walk(repoRoot)) {
      return walk.filter(Files::isRegularFile)
          .filter(HttpLegacyAdminBoundaryTest::isTrackedJavaSource)
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

  private static Set<String> readLegacyHttpImports(Path file) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .map(LEGACY_HTTP_IMPORT_PATTERN::matcher)
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
          .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    }
  }

  private static Set<String> forbiddenAdapterHttpImports(Path sourceFile) {
    if (sourceFile.equals(ADAPTER_N2NTM_TOADLET)) {
      return Set.of("import network.crypta.runtime.bootstrap.NodeStarter;");
    }
    if (sourceFile.equals(ADAPTER_QUEUE_TOADLET)) {
      return Set.of(
          "import network.crypta.runtime.admin.queue.page.QueueCompressionState;",
          "import network.crypta.runtime.admin.queue.page.QueueProgressCellContext;",
          "import network.crypta.runtime.admin.queue.page.QueueProgressCellRenderer;");
    }
    return Set.of();
  }

  private static boolean hasJavaSources(Path root) throws IOException {
    if (!Files.exists(root)) {
      return false;
    }
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .anyMatch(HttpLegacyAdminBoundaryTest::isTrackedJavaSource);
    }
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
