package network.crypta.platform.appdist;

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
class AppDistributionBoundaryTest {
  private static final String MODULE_NAME = "platform-appdist";
  private static final Path ROOT_PACKAGE =
      Path.of("src", "main", "java", "network", "crypta", "platform", "appdist");
  private static final Path MODULE_PACKAGE =
      Path.of(MODULE_NAME, "src", "main", "java", "network", "crypta", "platform", "appdist");
  private static final Path OWNERSHIP_METADATA =
      Path.of(MODULE_NAME, "gradle", "owned-output-patterns.txt");
  private static final Set<String> FORBIDDEN_IMPORT_PREFIXES =
      Set.of(
          "network.crypta.clients.",
          "network.crypta.runtime.",
          "network.crypta.node.",
          "network.crypta.client.",
          "network.crypta.platform.api.",
          "network.crypta.platform.apphost.",
          "network.crypta.launcher.");

  @Test
  void mainSourceLayout_whenCheckingLeafOwnership_expectDetachedAppdistTree() throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isDirectory(repoRoot.resolve(MODULE_PACKAGE)),
        ":platform-appdist must own network/crypta/platform/appdist main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_PACKAGE)),
        "Root project must not own network/crypta/platform/appdist main sources");
  }

  @Test
  void buildWiring_whenCheckingLeafMetadata_expectLeafDeclaredAndOwned() throws IOException {
    Path repoRoot = repoRoot();
    String settings = Files.readString(repoRoot.resolve("settings.gradle.kts"));
    String build = Files.readString(repoRoot.resolve("build.gradle.kts"));
    String moduleBuild =
        Files.readString(repoRoot.resolve(MODULE_NAME).resolve("build.gradle.kts"));
    String metadata = Files.readString(repoRoot.resolve(OWNERSHIP_METADATA));

    assertTrue(settings.contains("\":platform-appdist\""));
    assertTrue(build.contains("project(\":platform-appdist\")"));
    assertFalse(moduleBuild.contains("bcprov"));
    assertFalse(moduleBuild.contains("bcpkix"));
    assertTrue(metadata.contains("network/crypta/platform/appdist/**"));
  }

  @Test
  void mainSources_whenScanningImports_expectNoRuntimeOrApphostImports() throws IOException {
    Path repoRoot = repoRoot();
    Path mainJava = repoRoot.resolve(Path.of(MODULE_NAME, "src", "main", "java"));
    List<String> violations = new ArrayList<>();

    for (Path sourceFile : findJavaSources(mainJava)) {
      Set<String> imports = readForbiddenImports(sourceFile);
      if (!imports.isEmpty()) {
        violations.add(repoRoot.relativize(sourceFile) + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        ":platform-appdist main sources must stay free of runtime, adapter, launcher, client,"
            + " node, Platform API, and AppHost imports."
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

    for (Path sourceFile : findJavaSources(mainJava)) {
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
        "Every :platform-appdist main package with production Java files must declare"
            + " package-info.java."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), missingPackageInfos));
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .filter(AppDistributionBoundaryTest::isTrackedJavaSource)
          .sorted(Comparator.comparing(Path::toString))
          .toList();
    }
  }

  private static boolean isTrackedJavaSource(Path path) {
    String fileName = fileNameOrThrow(path);
    return fileName.endsWith(".java") && !fileName.startsWith("._");
  }

  private static Set<String> readForbiddenImports(Path file) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .filter(line -> line.startsWith("import "))
          .map(AppDistributionBoundaryTest::extractImportTarget)
          .filter(importTarget -> !importTarget.isEmpty())
          .filter(AppDistributionBoundaryTest::isForbiddenImport)
          .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    }
  }

  private static boolean isForbiddenImport(String importTarget) {
    return FORBIDDEN_IMPORT_PREFIXES.stream().anyMatch(importTarget::startsWith);
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
    while (directory != null && !looksLikeRepoRoot(directory)) {
      directory = directory.getParent();
    }
    assertNotNull(directory, "Could not locate the repo root from " + path.toAbsolutePath());
    return directory.toRealPath();
  }

  private static boolean looksLikeRepoRoot(Path directory) {
    return Files.isRegularFile(directory.resolve("settings.gradle.kts"))
        && Files.isRegularFile(directory.resolve("build.gradle.kts"))
        && Files.isDirectory(directory.resolve(MODULE_NAME));
  }
}
