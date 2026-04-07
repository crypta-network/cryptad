package network.crypta.platform.api;

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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PlatformApiBoundaryTest {
  private static final Path ROOT_PLATFORM_API_PACKAGE =
      Path.of("src", "main", "java", "network", "crypta", "platform", "api");
  private static final Path PLATFORM_API_MAIN_JAVA = Path.of("platform-api", "src", "main", "java");
  private static final Path PLATFORM_API_PACKAGE =
      Path.of("platform-api", "src", "main", "java", "network", "crypta", "platform", "api");
  private static final Path PLATFORM_API_ROUTER =
      PLATFORM_API_PACKAGE.resolve("PlatformApiRouter.java");
  private static final Path PLATFORM_API_JSON_ENCODER =
      PLATFORM_API_PACKAGE.resolve("json").resolve("PlatformApiJsonEncoder.java");
  private static final Pattern FORBIDDEN_IMPORT_PATTERN =
      Pattern.compile(
          "^import(?:\\s+static)?\\s+(network\\.crypta\\.(?:clients\\.(?:http|fcp)|node|client|runtime\\.(?:bootstrap|core|admin|endpoints))\\.[^;]+);$");

  @Test
  void mainSourceLayout_whenCheckingPlatformApiOwnership_expectLeafOwnsPackageTree()
      throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isDirectory(repoRoot.resolve(PLATFORM_API_PACKAGE)),
        ":platform-api must own network/crypta/platform/api main sources");
    assertFalse(
        Files.exists(repoRoot.resolve(ROOT_PLATFORM_API_PACKAGE)),
        "Root project must not own network/crypta/platform/api main sources");
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(PLATFORM_API_ROUTER)),
        ":platform-api must provide the Platform API router");
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(PLATFORM_API_JSON_ENCODER)),
        ":platform-api must provide the Platform API JSON encoder");
  }

  @Test
  void platformApiMain_whenScanningImports_expectNoAdapterOrRuntimeImplementationImports()
      throws IOException {
    Path repoRoot = repoRoot();
    Path platformApiMain = repoRoot.resolve(PLATFORM_API_MAIN_JAVA);
    List<String> violations = new ArrayList<>();

    assertTrue(Files.isDirectory(platformApiMain), ":platform-api main Java tree must exist");

    for (Path sourceFile : findJavaSources(platformApiMain)) {
      Set<String> imports = readForbiddenImports(sourceFile);
      if (!imports.isEmpty()) {
        violations.add(repoRoot.relativize(sourceFile) + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        ":platform-api main sources must stay above runtime-spi and free of adapter/daemon "
            + "implementation imports."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void platformApiMain_whenScanningProductionPackages_expectPackageInfoInEveryPackage()
      throws IOException {
    Path repoRoot = repoRoot();
    Path platformApiMain = repoRoot.resolve(PLATFORM_API_MAIN_JAVA);
    Set<Path> productionPackages = new TreeSet<>(Comparator.comparing(Path::toString));
    List<String> missingPackageInfos = new ArrayList<>();

    assertTrue(Files.isDirectory(platformApiMain), ":platform-api main Java tree must exist");

    for (Path sourceFile : findJavaSources(platformApiMain)) {
      String fileName = fileNameOrThrow(sourceFile);
      if (fileName.equals("package-info.java") || fileName.equals("module-info.java")) {
        continue;
      }
      productionPackages.add(parentOrThrow(sourceFile));
    }

    for (Path packagePath : productionPackages) {
      if (!Files.isRegularFile(packagePath.resolve("package-info.java"))) {
        missingPackageInfos.add(platformApiMain.relativize(packagePath).toString());
      }
    }

    assertTrue(
        missingPackageInfos.isEmpty(),
        "Every :platform-api main package with production Java files must declare"
            + " package-info.java."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), missingPackageInfos));
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .filter(PlatformApiBoundaryTest::isTrackedJavaSource)
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
          .map(FORBIDDEN_IMPORT_PATTERN::matcher)
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
    Path repoRoot = Path.of("").toAbsolutePath().normalize();
    assertTrue(Files.isRegularFile(repoRoot.resolve("settings.gradle.kts")));
    return repoRoot.toRealPath();
  }
}
