package network.crypta.clients.fcp.bridge;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class BridgeFcpRuntimeBoundaryTest {
  private static final String MODULE_NAME = "bridge-fcp-runtime";
  private static final Path ROOT_BRIDGE_MAIN_JAVA =
      Path.of("src", "main", "java", "network", "crypta", "clients", "fcp", "bridge");
  private static final Path ADAPTER_BRIDGE_MAIN_JAVA =
      Path.of(
          "adapter-fcp", "src", "main", "java", "network", "crypta", "clients", "fcp", "bridge");
  private static final Path BRIDGE_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "clients", "fcp", "bridge");
  private static final Path BRIDGE_BUILD_FILE = Path.of(MODULE_NAME, "build.gradle.kts");
  private static final Path ADAPTER_BUILD_FILE = Path.of("adapter-fcp", "build.gradle.kts");
  private static final Path OWNERSHIP_METADATA =
      Path.of(MODULE_NAME, "gradle", "owned-output-patterns.txt");
  private static final Path ADAPTER_OWNERSHIP_METADATA =
      Path.of("adapter-fcp", "gradle", "owned-output-patterns.txt");

  @Test
  void mainSourceLayout_whenCheckingBridgeOwnership_expectLeafOwnsPackageTree() throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isDirectory(repoRoot.resolve(BRIDGE_MAIN_JAVA)),
        ":bridge-fcp-runtime must own network/crypta/clients/fcp/bridge main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_BRIDGE_MAIN_JAVA)),
        "Root project must not own network/crypta/clients/fcp/bridge main sources");
    assertFalse(
        hasJavaSources(repoRoot.resolve(ADAPTER_BRIDGE_MAIN_JAVA)),
        ":adapter-fcp must not own network/crypta/clients/fcp/bridge main sources");
  }

  @Test
  void buildWiring_whenCheckingLeafMetadata_expectLeafDeclaredAndOwned() throws IOException {
    Path repoRoot = repoRoot();
    String settings = Files.readString(repoRoot.resolve("settings.gradle.kts"));
    String build = Files.readString(repoRoot.resolve("build.gradle.kts"));
    String bridgeBuild = Files.readString(repoRoot.resolve(BRIDGE_BUILD_FILE));
    String adapterBuild = Files.readString(repoRoot.resolve(ADAPTER_BUILD_FILE));
    Set<String> metadataPatterns = readOwnershipPatterns(repoRoot.resolve(OWNERSHIP_METADATA));
    Set<String> adapterMetadataPatterns =
        readOwnershipPatterns(repoRoot.resolve(ADAPTER_OWNERSHIP_METADATA));

    assertTrue(settings.contains("\":adapter-fcp\""));
    assertTrue(settings.contains("\":bridge-fcp-runtime\""));
    assertTrue(build.contains("project(\":adapter-fcp\")"));
    assertTrue(build.contains("project(\":bridge-fcp-runtime\")"));
    assertTrue(
        containsDirectProjectDependency(bridgeBuild, ":adapter-fcp"),
        ":bridge-fcp-runtime must depend on :adapter-fcp");
    assertTrue(
        containsDirectProjectDependency(bridgeBuild, ":runtime-node"),
        ":bridge-fcp-runtime must remain the concrete runtime-binding owner for FCP");
    assertFalse(
        containsDirectProjectDependency(adapterBuild, ":runtime-node"),
        ":adapter-fcp must not depend on :runtime-node");
    assertTrue(metadataPatterns.contains("network/crypta/clients/fcp/bridge/**"));
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(OWNERSHIP_METADATA)),
        ":bridge-fcp-runtime must declare owned-output-patterns.txt");
    assertTrue(adapterMetadataPatterns.contains("network/crypta/clients/fcp/*"));
    assertFalse(
        adapterMetadataPatterns.contains("network/crypta/clients/fcp/bridge/**"),
        ":adapter-fcp must not claim network/crypta/clients/fcp/bridge/**");
  }

  @Test
  void mainSources_whenScanningProductionPackages_expectPackageInfoInEveryPackage()
      throws IOException {
    Path repoRoot = repoRoot();
    Path bridgeMain = repoRoot.resolve(Path.of(MODULE_NAME, "src", "main", "java"));
    Set<Path> productionPackages = new TreeSet<>(Comparator.comparing(Path::toString));
    List<String> missingPackageInfos = new ArrayList<>();

    assertTrue(Files.isDirectory(bridgeMain), ":bridge-fcp-runtime main Java tree must exist");

    for (Path sourceFile : findJavaSources(bridgeMain)) {
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
        "Every :bridge-fcp-runtime main package with production Java files must declare "
            + "package-info.java."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), missingPackageInfos));
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .filter(BridgeFcpRuntimeBoundaryTest::isTrackedJavaSource)
          .sorted(Comparator.comparing(Path::toString))
          .toList();
    }
  }

  private static boolean isTrackedJavaSource(Path path) {
    String fileName = fileNameOrThrow(path);
    return fileName.endsWith(".java") && !fileName.startsWith("._");
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
    Pattern dependencyPattern =
        Pattern.compile(
            "(?m)^\\s*[A-Za-z][A-Za-z0-9_]*\\s*\\(\\s*project\\(\""
                + Pattern.quote(modulePath)
                + "\"\\)\\s*\\)");
    return dependencyPattern.matcher(buildScript).find();
  }

  private static boolean hasJavaSources(Path root) throws IOException {
    if (!Files.exists(root)) {
      return false;
    }
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .anyMatch(BridgeFcpRuntimeBoundaryTest::isTrackedJavaSource);
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
