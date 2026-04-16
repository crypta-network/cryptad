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
  private static final String BROWSE_MODULE_NAME = "adapter-http-legacy-browse";
  private static final String BRIDGE_MODULE_NAME = "bridge-http-runtime";
  private static final Path ROOT_HTTP_MAIN_JAVA =
      Path.of("src", "main", "java", "network", "crypta", "clients", "http");
  private static final Path ROOT_HTTP_MAIN_RESOURCES =
      Path.of("src", "main", "resources", "network", "crypta", "clients", "http");
  private static final Path ADAPTER_HTTP_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "clients", "http");
  private static final Path ADAPTER_CONFIG_TOADLET =
      ADAPTER_HTTP_MAIN_JAVA.resolve("ConfigToadlet.java");
  private static final Path BROWSE_HTTP_MAIN_JAVA =
      Path.of(BROWSE_MODULE_NAME, "src", "main", "java", "network", "crypta", "clients", "http");
  private static final Path ADAPTER_SIMPLE_TOADLET_SERVER =
      ADAPTER_HTTP_MAIN_JAVA.resolve("SimpleToadletServer.java");
  private static final Path ADAPTER_TOADLET_CONTEXT =
      ADAPTER_HTTP_MAIN_JAVA.resolve("ToadletContext.java");
  private static final Path ADAPTER_TOADLET_CONTEXT_IMPL =
      ADAPTER_HTTP_MAIN_JAVA.resolve("ToadletContextImpl.java");
  private static final Path ADAPTER_TOADLET_REQUEST_SERVICES =
      ADAPTER_HTTP_MAIN_JAVA.resolve("ToadletRequestServices.java");
  private static final Path ADAPTER_HTTP_SHELL_BROWSE_BOOTSTRAP =
      ADAPTER_HTTP_MAIN_JAVA.resolve("HttpShellBrowseBootstrap.java");
  private static final Path ADAPTER_PAGE_MAKER = ADAPTER_HTTP_MAIN_JAVA.resolve("PageMaker.java");
  private static final Path ADAPTER_INTERVAL_PUSHER_MANAGER =
      ADAPTER_HTTP_MAIN_JAVA.resolve("IntervalPusherManager.java");
  private static final Path ADAPTER_HTTP_SHELL_RUNTIME_SUPPORT =
      ADAPTER_HTTP_MAIN_JAVA.resolve("HttpShellRuntimeSupport.java");
  private static final Path ADAPTER_LEGACY_HTTP_BROWSE_ROUTE_REGISTRAR_CONTEXT =
      ADAPTER_HTTP_MAIN_JAVA.resolve("LegacyHttpBrowseRouteRegistrarContext.java");
  private static final Path ADAPTER_FPROXY_REGISTRAR_DEPENDENCIES =
      ADAPTER_HTTP_MAIN_JAVA.resolve("FProxyRegistrarDependencies.java");
  private static final String USER_ALERT_MANAGER_IMPORT =
      "import network.crypta.runtime.alerts.UserAlertManager;";
  private static final String PROGRAM_DIRECTORY_IMPORT =
      "import network.crypta.node.ProgramDirectory;";
  private static final Set<String> FORBIDDEN_RUNTIME_NODE_CLIENT_IMPORTS =
      Set.of(
          "import network.crypta.client.HighLevelSimpleClient;",
          "import network.crypta.client.FetchContext;",
          "import network.crypta.client.FetchWaiter;",
          "import network.crypta.client.InsertContext;",
          "import network.crypta.client.InsertContext.CompatibilityMode;");
  private static final Set<String> FORBIDDEN_LEAF_HELPER_IMPORTS =
      Set.of(
          "import network.crypta.client.filter.HTMLFilter;",
          "import network.crypta.support.io.FileUtil;",
          "import network.crypta.support.io.FileUtil.OperatingSystem;",
          "import network.crypta.support.io.DatastoreUtil;");
  private static final Path ADAPTER_HTTP_FPROXY_BOOTSTRAP =
      ADAPTER_HTTP_MAIN_JAVA.resolve("HttpShellFProxyBootstrap.java");
  private static final Path ADAPTER_LEGACY_ADMIN_HTTP_ROUTE_REGISTRAR =
      ADAPTER_HTTP_MAIN_JAVA.resolve("LegacyAdminHttpRouteRegistrar.java");
  private static final Path ADAPTER_FPROXY_REGISTRAR =
      ADAPTER_HTTP_MAIN_JAVA.resolve("FProxyRegistrar.java");
  private static final Path ADAPTER_LEGACY_HTTP_ROUTE_REGISTRAR_CONTEXT =
      ADAPTER_HTTP_MAIN_JAVA.resolve("LegacyHttpRouteRegistrarContext.java");
  private static final Path ADAPTER_N2NTM_TOADLET =
      ADAPTER_HTTP_MAIN_JAVA.resolve("N2NTMToadlet.java");
  private static final Path ADAPTER_QUEUE_TOADLET =
      ADAPTER_HTTP_MAIN_JAVA.resolve("QueueToadlet.java");
  private static final Path ADAPTER_WEB_SHELL_TOADLET =
      ADAPTER_HTTP_MAIN_JAVA.resolve("WebShellToadlet.java");
  private static final List<Path> CONNECTIONS_TOADLETS =
      List.of(
          ADAPTER_HTTP_MAIN_JAVA.resolve("ConnectionsToadlet.java"),
          ADAPTER_HTTP_MAIN_JAVA.resolve("DarknetConnectionsToadlet.java"),
          ADAPTER_HTTP_MAIN_JAVA.resolve("OpennetConnectionsToadlet.java"));
  private static final List<Path> SHARED_SHELL_FILES_WITH_BROWSE_OWNED_COLLABORATORS =
      List.of(
          ADAPTER_SIMPLE_TOADLET_SERVER,
          ADAPTER_TOADLET_CONTEXT,
          ADAPTER_TOADLET_CONTEXT_IMPL,
          ADAPTER_TOADLET_REQUEST_SERVICES,
          ADAPTER_HTTP_SHELL_BROWSE_BOOTSTRAP,
          ADAPTER_PAGE_MAKER,
          ADAPTER_INTERVAL_PUSHER_MANAGER);
  private static final List<String> FORBIDDEN_BROWSE_OWNED_COLLABORATOR_IMPORTS =
      List.of(
          "import network.crypta.clients.http.bookmark.BookmarkManager;",
          "import network.crypta.clients.http.updateableelements.PushDataManager;",
          "import network.crypta.clients.http.updateableelements.BaseUpdatableElement;",
          "import network.crypta.clients.http.filter.PushingTagReplacerCallback;");
  private static final Path ADAPTER_HTTP_MAIN_RESOURCES =
      Path.of(MODULE_NAME, "src", "main", "resources", "network", "crypta", "clients", "http");
  private static final Path ADAPTER_BUILD_FILE = Path.of(MODULE_NAME, "build.gradle.kts");
  private static final Path BROWSE_BUILD_FILE = Path.of(BROWSE_MODULE_NAME, "build.gradle.kts");
  private static final Path BROWSE_OWNERSHIP_METADATA =
      Path.of(BROWSE_MODULE_NAME, "gradle", "owned-output-patterns.txt");
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
  private static final List<String> MOVED_BROWSE_TOP_LEVEL_FILES =
      List.of(
          "BookmarkEditorToadlet.java",
          "BookmarkEditorToadletRuntimePorts.java",
          "BrowserTestToadlet.java",
          "ContentFilterToadlet.java",
          "DecodeToadlet.java",
          "ExternalLinkToadlet.java",
          "FProxyFetchCriteria.java",
          "FProxyFetchInProgress.java",
          "FProxyFetchListener.java",
          "FProxyFetchProgressCounts.java",
          "FProxyFetchResult.java",
          "FProxyFetchSnapshotInfo.java",
          "FProxyFetchTracker.java",
          "FProxyFetchWaiter.java",
          "FProxyRuntimeSupport.java",
          "FProxyToadlet.java",
          "HTTPRangeException.java",
          "ImageCreatorToadlet.java",
          "InsertFreesiteToadlet.java",
          "LegacyFProxyAjaxPushRouteRegistrar.java",
          "LegacyFProxyBrowseRouteRegistrar.java",
          "LocalFileFilterToadlet.java",
          "RssSniffer.java",
          "WelcomeToadlet.java",
          "WelcomeToadletRuntimePorts.java");
  private static final List<String> MOVED_BROWSE_PACKAGE_DIRS =
      List.of("ajaxpush", "bookmark", "complexhtmlnodes", "filter", "updateableelements");
  private static final Set<String> FORBIDDEN_ADAPTER_HTTP_IMPORTS =
      Set.of(
          "import network.crypta.node.PeerNodeStatus;",
          "import network.crypta.node.DarknetPeerNodeStatus;",
          "import network.crypta.node.OpennetPeerNodeStatus;",
          "import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;",
          "import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;",
          "import network.crypta.node.Version;",
          "import network.crypta.runtime.peers.reference.PeerReferenceTextLoader;",
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
        Files.isDirectory(repoRoot.resolve(BROWSE_HTTP_MAIN_JAVA)),
        ":adapter-http-legacy-browse must own network/crypta/clients/http main sources");
    assertTrue(
        Files.isDirectory(repoRoot.resolve(ADAPTER_HTTP_MAIN_RESOURCES)),
        "adapter-http-legacy-admin must own network/crypta/clients/http main resources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_HTTP_MAIN_JAVA)),
        "Root project must not re-own network/crypta/clients/http main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_HTTP_MAIN_RESOURCES)),
        "Root project must not re-own network/crypta/clients/http main resources");
    for (String fileName : MOVED_BROWSE_TOP_LEVEL_FILES) {
      assertFalse(
          Files.exists(repoRoot.resolve(ADAPTER_HTTP_MAIN_JAVA.resolve(fileName))),
          "adapter-http-legacy-admin must not own moved browse file " + fileName);
    }
    for (String packageDir : MOVED_BROWSE_PACKAGE_DIRS) {
      assertFalse(
          hasJavaSources(repoRoot.resolve(ADAPTER_HTTP_MAIN_JAVA.resolve(packageDir))),
          "adapter-http-legacy-admin must not own moved browse package " + packageDir);
    }
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
  void buildWiring_whenCheckingLeafMetadata_expectLeafDeclaredAndOwned() throws IOException {
    Path repoRoot = repoRoot();
    String settings = Files.readString(repoRoot.resolve("settings.gradle.kts"));
    String build = Files.readString(repoRoot.resolve("build.gradle.kts"));
    String adapterBuild = Files.readString(repoRoot.resolve(ADAPTER_BUILD_FILE));
    String browseBuild = Files.readString(repoRoot.resolve(BROWSE_BUILD_FILE));
    String browseMetadata = Files.readString(repoRoot.resolve(BROWSE_OWNERSHIP_METADATA));
    String bridgeMetadata = Files.readString(repoRoot.resolve(BRIDGE_OWNERSHIP_METADATA));
    String adapterMetadata = Files.readString(repoRoot.resolve(OWNERSHIP_METADATA));

    assertTrue(settings.contains("\":bridge-http-runtime\""));
    assertTrue(settings.contains("\":adapter-http-legacy-browse\""));
    assertTrue(build.contains("project(\":bridge-http-runtime\")"));
    assertTrue(build.contains("project(\":adapter-http-legacy-browse\")"));
    assertTrue(settings.contains("\":adapter-http-legacy-admin\""));
    assertTrue(build.contains("project(\":adapter-http-legacy-admin\")"));
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(BROWSE_OWNERSHIP_METADATA)),
        ":adapter-http-legacy-browse must declare owned-output-patterns.txt");
    assertTrue(
        browseMetadata.contains("network/crypta/clients/http/ContentToadlet*.class"),
        ":adapter-http-legacy-browse must own network/crypta/clients/http/ContentToadlet*.class");
    assertTrue(
        browseBuild.contains("project(\":adapter-http-legacy-admin\")"),
        ":adapter-http-legacy-browse must depend on :adapter-http-legacy-admin");
    assertFalse(
        adapterBuild.contains("project(\":adapter-http-legacy-browse\")"),
        ":adapter-http-legacy-admin must not depend on :adapter-http-legacy-browse");
    assertFalse(
        containsDirectProjectDependency(adapterBuild, ":runtime-node"),
        ":adapter-http-legacy-admin must not depend on :runtime-node");
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
    assertFalse(
        adapterMetadata.contains("network/crypta/clients/http/ContentToadlet*.class"),
        ":adapter-http-legacy-admin must not claim ContentToadlet*.class");
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
          && !relativePath.startsWith(BROWSE_HTTP_MAIN_JAVA)
          && !relativePath.startsWith(BRIDGE_HTTP_MAIN_JAVA)
          && !relativePath.startsWith(BRIDGE_GEOIP_MAIN_JAVA)) {
        violations.add(relativePath + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Only adapter-http-legacy-admin, adapter-http-legacy-browse, bridge-http-runtime, and "
            + "the bootstrap binding site may import network.crypta.clients.http.*."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
    assertEquals(
        EXPECTED_DEFAULT_BRIDGE_FACTORIES_HTTP_IMPORTS,
        bootstrapHttpImports,
        "DefaultNodeRuntimeBridgeFactories must be the only bootstrap-owned HTTP binding "
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
  void mainSources_whenCheckingSharedShellImports_expectBrowseOwnedCollaboratorsDetached()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path sourceFile : SHARED_SHELL_FILES_WITH_BROWSE_OWNED_COLLABORATORS) {
      Set<String> imports = readImports(repoRoot.resolve(sourceFile));
      for (String forbiddenImport : FORBIDDEN_BROWSE_OWNED_COLLABORATOR_IMPORTS) {
        if (imports.contains(forbiddenImport)) {
          violations.add(sourceFile + " -> " + forbiddenImport);
        }
      }
    }

    assertTrue(
        violations.isEmpty(),
        "SimpleToadletServer, ToadletContext, ToadletContextImpl, ToadletRequestServices, "
            + "HttpShellBrowseBootstrap, PageMaker, and IntervalPusherManager must not import "
            + "browse-owned bookmark, push, or client-script collaborators."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void mainSources_whenCheckingAdminHttpImports_expectRuntimeNodeClientContractsRemoved()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path sourceFile : findMainJavaSources(repoRoot)) {
      Path relativePath = repoRoot.relativize(sourceFile);
      if (!relativePath.startsWith(ADAPTER_HTTP_MAIN_JAVA)) {
        continue;
      }

      Set<String> imports = readImports(sourceFile);
      for (String forbiddenImport : FORBIDDEN_RUNTIME_NODE_CLIENT_IMPORTS) {
        if (imports.contains(forbiddenImport)) {
          violations.add(relativePath + " -> " + forbiddenImport);
        }
      }
    }

    assertTrue(
        violations.isEmpty(),
        "adapter-http-legacy-admin main sources must not import runtime-node client contracts "
            + "directly anymore."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void mainSources_whenScanningAdminLeafHelperImports_expectDetachedImportsAbsent()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path sourceFile : findMainJavaSources(repoRoot)) {
      Path relativePath = repoRoot.relativize(sourceFile);
      if (!relativePath.startsWith(ADAPTER_HTTP_MAIN_JAVA)) {
        continue;
      }

      Set<String> imports = readImports(sourceFile);
      for (String forbiddenImport : FORBIDDEN_LEAF_HELPER_IMPORTS) {
        if (imports.contains(forbiddenImport)) {
          violations.add(relativePath + " -> " + forbiddenImport);
        }
      }
    }

    assertTrue(
        violations.isEmpty(),
        "adapter-http-legacy-admin main sources must not import HTMLFilter, FileUtil, or "
            + "DatastoreUtil directly anymore."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void mainSources_whenCheckingAdminBrowseSeam_expectRegistrarContextsDetached()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path sourceFile :
        List.of(
            ADAPTER_HTTP_SHELL_BROWSE_BOOTSTRAP,
            ADAPTER_LEGACY_HTTP_BROWSE_ROUTE_REGISTRAR_CONTEXT,
            ADAPTER_FPROXY_REGISTRAR_DEPENDENCIES,
            ADAPTER_HTTP_SHELL_RUNTIME_SUPPORT,
            ADAPTER_LEGACY_ADMIN_HTTP_ROUTE_REGISTRAR,
            ADAPTER_FPROXY_REGISTRAR,
            ADAPTER_LEGACY_HTTP_ROUTE_REGISTRAR_CONTEXT,
            ADAPTER_QUEUE_TOADLET,
            ADAPTER_HTTP_MAIN_JAVA.resolve("FileInsertWizardToadlet.java"))) {
      String source = Files.readString(repoRoot.resolve(sourceFile));
      if (source.contains("HighLevelSimpleClient")) {
        violations.add(sourceFile + " -> HighLevelSimpleClient");
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Admin-owned legacy HTTP seam classes should no longer mention HighLevelSimpleClient."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void mainSources_whenCheckingBrowseNeutralShellSeam_expectNoSharedFProxyToadletLeaks()
      throws IOException {
    Path repoRoot = repoRoot();
    String simpleToadletServerSource =
        Files.readString(repoRoot.resolve(ADAPTER_SIMPLE_TOADLET_SERVER));
    String runtimeSupportSource =
        Files.readString(repoRoot.resolve(ADAPTER_HTTP_SHELL_RUNTIME_SUPPORT));
    String legacyAdminRouteRegistrarSource =
        Files.readString(repoRoot.resolve(ADAPTER_LEGACY_ADMIN_HTTP_ROUTE_REGISTRAR));
    String routeRegistrarContextSource =
        Files.readString(repoRoot.resolve(ADAPTER_LEGACY_HTTP_ROUTE_REGISTRAR_CONTEXT));
    String queueToadletSource = Files.readString(repoRoot.resolve(ADAPTER_QUEUE_TOADLET));
    String webShellToadletSource = Files.readString(repoRoot.resolve(ADAPTER_WEB_SHELL_TOADLET));
    String n2ntmToadletSource = Files.readString(repoRoot.resolve(ADAPTER_N2NTM_TOADLET));

    assertFalse(
        Files.exists(repoRoot.resolve(ADAPTER_HTTP_FPROXY_BOOTSTRAP)),
        "The shared shell must not keep the old FProxy-specific bootstrap type.");
    assertFalse(
        simpleToadletServerSource.contains("FProxyToadlet"),
        repoRoot.resolve(ADAPTER_SIMPLE_TOADLET_SERVER) + " must not contain FProxyToadlet");
    assertFalse(
        runtimeSupportSource.contains("FProxyToadlet"),
        repoRoot.resolve(ADAPTER_HTTP_SHELL_RUNTIME_SUPPORT) + " must not contain FProxyToadlet");
    assertFalse(
        legacyAdminRouteRegistrarSource.contains("FProxyToadlet"),
        repoRoot.resolve(ADAPTER_LEGACY_ADMIN_HTTP_ROUTE_REGISTRAR)
            + " must not contain FProxyToadlet");
    assertFalse(
        routeRegistrarContextSource.contains("FProxyToadlet"),
        repoRoot.resolve(ADAPTER_LEGACY_HTTP_ROUTE_REGISTRAR_CONTEXT)
            + " must not contain FProxyToadlet");
    for (String forbiddenReference :
        List.of(
            "FProxyToadlet.DOWNLOADS_PATH",
            "FProxyToadlet.FRIENDS_PATH",
            "FProxyToadlet.CONFIG_PATH",
            "FProxyToadlet.WELCOME_PATH",
            "FProxyToadlet.CATEGORY_BROWSING",
            "FProxyToadlet.CATEGORY_QUEUE",
            "FProxyToadlet.CATEGORY_FRIENDS",
            "FProxyToadlet.CATEGORY_STATUS",
            "FProxyToadlet.CATEGORY_CONFIG")) {
      assertFalse(
          queueToadletSource.contains(forbiddenReference),
          repoRoot.resolve(ADAPTER_QUEUE_TOADLET) + " must not contain " + forbiddenReference);
    }
    assertFalse(
        webShellToadletSource.contains("FProxyToadlet"),
        repoRoot.resolve(ADAPTER_WEB_SHELL_TOADLET) + " must not contain FProxyToadlet");
    assertFalse(
        n2ntmToadletSource.contains("FProxyToadlet"),
        repoRoot.resolve(ADAPTER_N2NTM_TOADLET) + " must not contain FProxyToadlet");
  }

  @Test
  void mainSources_whenCheckingBrowseConstructionLeaks_expectNoConcreteBrowseBootstrapTypes()
      throws IOException {
    Path repoRoot = repoRoot();

    assertSourceDoesNotContainAny(
        repoRoot.resolve(ADAPTER_HTTP_SHELL_BROWSE_BOOTSTRAP),
        List.of(
            "FProxyToadlet",
            "FProxyRuntimeSupport",
            "FProxyFetchTracker",
            "PushDataManagerHandles",
            "network.crypta.clients.http.updateableelements.PushDataManager"));
    assertSourceDoesNotContainAny(
        repoRoot.resolve(ADAPTER_HTTP_SHELL_RUNTIME_SUPPORT),
        List.of(
            "FProxyToadlet",
            "FProxyRuntimeSupport",
            "FProxyFetchTracker",
            "PushDataManagerHandles",
            "network.crypta.clients.http.updateableelements.PushDataManager"));
    assertSourceDoesNotContainAny(
        repoRoot.resolve(ADAPTER_SIMPLE_TOADLET_SERVER),
        List.of(
            "FProxyToadlet",
            "FProxyRuntimeSupport",
            "FProxyFetchTracker",
            "FProxyToadlet.random",
            "PushDataManagerHandles",
            "PushDataManagerHandles.create(",
            "network.crypta.clients.http.updateableelements.PushDataManager"));
  }

  @Test
  void mainSources_whenCheckingAdminCallers_expectBrowseStaticReferencesNeutralized()
      throws IOException {
    Path repoRoot = repoRoot();
    List<Path> files =
        List.of(
            ADAPTER_QUEUE_TOADLET,
            ADAPTER_SIMPLE_TOADLET_SERVER,
            ADAPTER_HTTP_MAIN_JAVA.resolve("FileInsertWizardToadlet.java"),
            ADAPTER_HTTP_MAIN_JAVA.resolve("StartupToadlet.java"),
            ADAPTER_HTTP_MAIN_JAVA.resolve("FirstTimeWizardToadlet.java"),
            ADAPTER_HTTP_MAIN_JAVA.resolve("FirstTimeWizardNewToadlet.java"),
            ADAPTER_HTTP_MAIN_JAVA.resolve("SecurityLevelsToadlet.java"),
            ADAPTER_HTTP_MAIN_JAVA.resolve("wizardsteps").resolve("SecurityPhysical.java"));

    for (Path file : files) {
      String source = Files.readString(repoRoot.resolve(file));
      assertFalse(source.contains("WelcomeToadlet."), file + " must not reference WelcomeToadlet.");
      assertFalse(
          source.contains("ContentFilterToadlet."),
          file + " must not reference ContentFilterToadlet.");
      assertFalse(
          source.contains("ExternalLinkToadlet."),
          file + " must not reference ExternalLinkToadlet.");
    }
  }

  @Test
  void
      mainSources_whenCheckingAdminOwnedRouteRegistration_expectBrowseConstructionDelegatedThroughSeam()
          throws IOException {
    Path repoRoot = repoRoot();
    String legacyAdminRouteRegistrarSource =
        Files.readString(repoRoot.resolve(ADAPTER_LEGACY_ADMIN_HTTP_ROUTE_REGISTRAR));
    String fproxyRegistrarSource = Files.readString(repoRoot.resolve(ADAPTER_FPROXY_REGISTRAR));

    assertTrue(
        legacyAdminRouteRegistrarSource.contains("context.browseRouteRegistrar()"),
        repoRoot.resolve(ADAPTER_LEGACY_ADMIN_HTTP_ROUTE_REGISTRAR)
            + " must forward the browse-route registrar seam.");
    assertTrue(
        fproxyRegistrarSource.contains("browseRouteRegistrar.registerRoutes("),
        repoRoot.resolve(ADAPTER_FPROXY_REGISTRAR)
            + " must delegate browse-owned route publication through the neutral seam.");
    assertSourceDoesNotContainAny(
        repoRoot.resolve(ADAPTER_LEGACY_ADMIN_HTTP_ROUTE_REGISTRAR),
        List.of(
            "new DecodeToadlet(",
            "new InsertFreesiteToadlet(",
            "new ContentFilterToadlet(",
            "new LocalFileFilterToadlet(",
            "new WelcomeToadlet(",
            "new ExternalLinkToadlet(",
            "new BookmarkEditorToadlet(",
            "new BrowserTestToadlet(",
            "new ImageCreatorToadlet(",
            "new PushDataToadlet(",
            "new PushNotificationToadlet(",
            "new PushKeepaliveToadlet(",
            "new PushFailoverToadlet(",
            "new PushTesterToadlet(",
            "new PushLeavingToadlet(",
            "new LogWritebackToadlet(",
            "new DismissAlertToadlet(",
            "new LegacyFProxyBrowseRouteRegistrar("));
    assertSourceDoesNotContainAny(
        repoRoot.resolve(ADAPTER_FPROXY_REGISTRAR),
        List.of(
            "new DecodeToadlet(",
            "new InsertFreesiteToadlet(",
            "new ContentFilterToadlet(",
            "new LocalFileFilterToadlet(",
            "new WelcomeToadlet(",
            "new ExternalLinkToadlet(",
            "new BookmarkEditorToadlet(",
            "new BrowserTestToadlet(",
            "new ImageCreatorToadlet(",
            "new PushDataToadlet(",
            "new PushNotificationToadlet(",
            "new PushKeepaliveToadlet(",
            "new PushFailoverToadlet(",
            "new PushTesterToadlet(",
            "new PushLeavingToadlet(",
            "new LogWritebackToadlet(",
            "new DismissAlertToadlet("));
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
  void mainSources_whenCheckingSharedShellAlertImports_expectDetachedAlertSurfaceUsed()
      throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();

    for (Path sourceFile :
        List.of(
            ADAPTER_HTTP_SHELL_RUNTIME_SUPPORT,
            ADAPTER_TOADLET_CONTEXT,
            ADAPTER_TOADLET_CONTEXT_IMPL,
            ADAPTER_TOADLET_REQUEST_SERVICES,
            ADAPTER_SIMPLE_TOADLET_SERVER)) {
      Set<String> imports = readImports(repoRoot.resolve(sourceFile));
      if (imports.contains(USER_ALERT_MANAGER_IMPORT)) {
        violations.add(sourceFile + " -> " + USER_ALERT_MANAGER_IMPORT);
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Shared HTTP/admin shell sources must use the detached runtime-alerts surface instead of "
            + "importing UserAlertManager directly."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void mainSources_whenCheckingConfigToadletImports_expectProgramDirectoryImportRemoved()
      throws IOException {
    Path repoRoot = repoRoot();
    Set<String> imports = readImports(repoRoot.resolve(ADAPTER_CONFIG_TOADLET));

    assertFalse(
        imports.contains(PROGRAM_DIRECTORY_IMPORT),
        repoRoot.resolve(ADAPTER_CONFIG_TOADLET)
            + " must use the detached config directory-selection marker instead of importing "
            + "ProgramDirectory directly.");
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

  private static Set<String> readImports(Path file) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .filter(line -> line.startsWith("import "))
          .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    }
  }

  private static void assertSourceDoesNotContainAny(Path file, List<String> forbiddenReferences)
      throws IOException {
    String source = Files.readString(file);
    List<String> violations = new ArrayList<>();

    for (String forbiddenReference : forbiddenReferences) {
      if (source.contains(forbiddenReference)) {
        violations.add(forbiddenReference);
      }
    }

    assertTrue(
        violations.isEmpty(),
        file
            + " must not contain any of: "
            + forbiddenReferences
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
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
