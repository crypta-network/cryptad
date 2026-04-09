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
  private static final Path ADAPTER_FCP_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "clients", "fcp");
  private static final Path OWNERSHIP_METADATA =
      Path.of(MODULE_NAME, "gradle", "owned-output-patterns.txt");
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

  @Test
  void mainSourceLayout_whenCheckingFcpOwnership_expectLeafOwnsPackageTree() throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isDirectory(repoRoot.resolve(ADAPTER_FCP_MAIN_JAVA)),
        "adapter-fcp must own network/crypta/clients/fcp main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_FCP_MAIN_JAVA)),
        "Root project must not re-own network/crypta/clients/fcp main sources");
  }

  @Test
  void buildWiring_whenCheckingLeafMetadata_expectOwnedOutputPatternDeclared() throws IOException {
    Path repoRoot = repoRoot();
    String settings = Files.readString(repoRoot.resolve("settings.gradle.kts"));
    String build = Files.readString(repoRoot.resolve("build.gradle.kts"));
    String metadata = Files.readString(repoRoot.resolve(OWNERSHIP_METADATA));

    assertTrue(settings.contains("\":adapter-fcp\""));
    assertTrue(build.contains("project(\":adapter-fcp\")"));
    assertTrue(metadata.contains("network/crypta/clients/fcp/**"));
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
      if (!imports.isEmpty() && !relativePath.startsWith(ADAPTER_FCP_MAIN_JAVA)) {
        violations.add(relativePath + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Only :adapter-fcp main sources may import network.crypta.clients.fcp.*, except the "
            + "bootstrap binding site and the AddRef tool."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
    assertEquals(
        EXPECTED_DEFAULT_BRIDGE_FACTORIES_IMPORTS,
        bootstrapImports,
        "DefaultNodeRuntimeBridgeFactories must remain the narrow bootstrap-owned FCP binding "
            + "site");
    assertEquals(
        EXPECTED_ADD_REF_IMPORTS,
        addRefImports,
        "AddRef must remain the narrow tool-owned FCP exception");
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
