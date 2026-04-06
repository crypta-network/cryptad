package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppHostBoundaryTest {
  private static final String MODULE_NAME = "platform-apphost";
  private static final Path ROOT_APPHOST_MAIN_JAVA =
      Path.of("src", "main", "java", "network", "crypta", "platform", "apphost");
  private static final Path APPHOST_MAIN_JAVA =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "platform", "apphost");
  private static final Path OWNERSHIP_METADATA =
      Path.of(MODULE_NAME, "gradle", "owned-output-patterns.txt");
  private static final Set<String> FORBIDDEN_IMPORT_PREFIXES =
      Set.of(
          "network.crypta.clients.",
          "network.crypta.runtime.",
          "network.crypta.node.",
          "network.crypta.client.",
          "network.crypta.platform.api.",
          "network.crypta.launcher.");

  @Test
  void mainSourceLayout_whenCheckingAppHostOwnership_expectLeafOwnsPackageTree()
      throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isDirectory(repoRoot.resolve(APPHOST_MAIN_JAVA)),
        ":platform-apphost must own network/crypta/platform/apphost main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_APPHOST_MAIN_JAVA)),
        "Root project must not own network/crypta/platform/apphost main sources");
  }

  @Test
  void buildWiring_whenCheckingSettingsAndOwnershipMetadata_expectLeafDeclaredAndOwned()
      throws IOException {
    Path repoRoot = repoRoot();
    String settings = Files.readString(repoRoot.resolve("settings.gradle.kts"));
    String build = Files.readString(repoRoot.resolve("build.gradle.kts"));
    String metadata = Files.readString(repoRoot.resolve(OWNERSHIP_METADATA));

    assertTrue(settings.contains("\":platform-apphost\""));
    assertTrue(build.contains("project(\":platform-apphost\")"));
    assertTrue(metadata.contains("network/crypta/platform/apphost/**"));
  }

  @Test
  void mainSources_whenScanningAppHostImports_expectNoRuntimeOrAdapterImports() throws IOException {
    Path repoRoot = repoRoot();
    List<String> violations = new ArrayList<>();
    Path mainJava = repoRoot.resolve(Path.of(MODULE_NAME, "src", "main", "java"));

    for (Path sourceFile : findJavaSources(mainJava)) {
      Set<String> imports = readForbiddenImports(sourceFile);
      if (!imports.isEmpty()) {
        violations.add(repoRoot.relativize(sourceFile) + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        ":platform-apphost main sources must stay free of runtime, adapter, launcher, client, "
            + "node, and Platform API implementation imports."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void mainSources_whenScanningProductionPackages_expectPackageInfoInEveryPackage()
      throws IOException {
    Path repoRoot = repoRoot();
    Path mainJava = repoRoot.resolve(Path.of(MODULE_NAME, "src", "main", "java"));
    Set<Path> productionPackages = new TreeSet<>(Comparator.comparing(Path::toString));
    List<String> missingPackageInfos = new ArrayList<>();

    assertTrue(
        Files.isDirectory(repoRoot.resolve(APPHOST_MAIN_JAVA)),
        ":platform-apphost main Java tree must exist");

    for (Path sourceFile : findJavaSources(mainJava)) {
      String fileName = sourceFile.getFileName().toString();
      if (fileName.equals("package-info.java") || fileName.equals("module-info.java")) {
        continue;
      }
      productionPackages.add(sourceFile.getParent());
    }

    for (Path packagePath : productionPackages) {
      if (!Files.isRegularFile(packagePath.resolve("package-info.java"))) {
        missingPackageInfos.add(repoRoot.relativize(packagePath).toString());
      }
    }

    assertTrue(
        missingPackageInfos.isEmpty(),
        "Every :platform-apphost main package with production Java files must declare "
            + "package-info.java."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), missingPackageInfos));
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .filter(AppHostBoundaryTest::isTrackedJavaSource)
          .sorted(Comparator.comparing(Path::toString))
          .toList();
    }
  }

  private static boolean isTrackedJavaSource(Path path) {
    String fileName = path.getFileName().toString();
    return fileName.endsWith(".java") && !fileName.startsWith("._");
  }

  private static Set<String> readForbiddenImports(Path file) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .filter(line -> line.startsWith("import "))
          .map(AppHostBoundaryTest::extractImportTarget)
          .filter(importTarget -> !importTarget.isEmpty())
          .filter(AppHostBoundaryTest::isForbiddenImport)
          .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    }
  }

  private static String extractImportTarget(String line) {
    String importTarget = line.substring("import ".length()).trim();
    if (importTarget.startsWith("static ")) {
      importTarget = importTarget.substring("static ".length()).trim();
    }
    return importTarget.endsWith(";")
        ? importTarget.substring(0, importTarget.length() - 1)
        : importTarget;
  }

  private static boolean isForbiddenImport(String importTarget) {
    return FORBIDDEN_IMPORT_PREFIXES.stream().anyMatch(importTarget::startsWith);
  }

  private static Path repoRoot() throws IOException {
    Path directory = Path.of("").toAbsolutePath().normalize();
    while (directory != null && !Files.isRegularFile(directory.resolve("settings.gradle.kts"))) {
      directory = directory.getParent();
    }
    assertNotNull(directory, "Could not locate the repo root from " + Path.of("").toAbsolutePath());
    return directory.toRealPath();
  }
}
