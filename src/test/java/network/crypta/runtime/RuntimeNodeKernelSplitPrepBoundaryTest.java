package network.crypta.runtime;

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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class RuntimeNodeKernelSplitPrepBoundaryTest {
  private static final Path ROOT_MAIN_PACKAGE = Path.of("src", "main", "java", "network", "crypta");
  private static final Path ROOT_BOOTSTRAP_PACKAGE =
      Path.of("src", "main", "java", "network", "crypta", "runtime", "bootstrap");
  private static final Path ROOT_TOOLS_PACKAGE =
      Path.of("src", "main", "java", "network", "crypta", "tools");
  private static final Path RUNTIME_NODE_MAIN_JAVA = Path.of("runtime-node", "src", "main", "java");
  private static final Pattern ADAPTER_IMPORT_PATTERN =
      Pattern.compile(
          "^import(?:\\s+static)?\\s+(network\\.crypta\\.clients\\.(?:fcp|http)\\.[^;]+);$");

  @Test
  void rootMainJava_whenScanningPackages_expectOnlyBootstrapAndToolsOwnership() throws IOException {
    Path repoRoot = repoRoot();
    Path rootMainPackage = repoRoot.resolve(ROOT_MAIN_PACKAGE);
    List<String> violations = new ArrayList<>();

    assertTrue(Files.isDirectory(rootMainPackage), "Root main package tree must exist");

    for (Path sourceFile : findJavaSources(rootMainPackage)) {
      Path relativePath = repoRoot.relativize(sourceFile);
      if (!relativePath.startsWith(ROOT_BOOTSTRAP_PACKAGE)
          && !relativePath.startsWith(ROOT_TOOLS_PACKAGE)) {
        violations.add(relativePath.toString());
      }
    }

    assertTrue(
        violations.isEmpty(),
        "Root src/main/java/network/crypta must stay limited to runtime/bootstrap and tools."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void runtimeNodeMain_whenScanningImports_expectNoAdapterImports() throws IOException {
    Path repoRoot = repoRoot();
    Path runtimeNodeMain = repoRoot.resolve(RUNTIME_NODE_MAIN_JAVA);
    List<String> violations = new ArrayList<>();

    assertTrue(Files.isDirectory(runtimeNodeMain), "runtime-node main Java tree must exist");

    for (Path sourceFile : findJavaSources(runtimeNodeMain)) {
      Set<String> imports = readAdapterImports(sourceFile);
      if (!imports.isEmpty()) {
        violations.add(repoRoot.relativize(sourceFile) + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "runtime-node main sources must stay free of adapter imports."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void runtimeNodeMain_whenScanningProductionPackages_expectPackageInfoInEveryPackage()
      throws IOException {
    Path repoRoot = repoRoot();
    Path runtimeNodeMain = repoRoot.resolve(RUNTIME_NODE_MAIN_JAVA);
    Set<Path> productionPackages = new TreeSet<>(Comparator.comparing(Path::toString));
    List<String> missingPackageInfos = new ArrayList<>();

    assertTrue(Files.isDirectory(runtimeNodeMain), "runtime-node main Java tree must exist");

    for (Path sourceFile : findJavaSources(runtimeNodeMain)) {
      String fileName = fileNameOrThrow(sourceFile);
      if (fileName.equals("package-info.java") || fileName.equals("module-info.java")) {
        continue;
      }
      productionPackages.add(parentOrThrow(sourceFile));
    }

    for (Path packagePath : productionPackages) {
      Path packageInfo = packagePath.resolve("package-info.java");
      if (!Files.isRegularFile(packageInfo)) {
        missingPackageInfos.add(runtimeNodeMain.relativize(packagePath).toString());
      }
    }

    assertTrue(
        missingPackageInfos.isEmpty(),
        "Every runtime-node main package with production Java files must declare package-info.java."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), missingPackageInfos));
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .filter(RuntimeNodeKernelSplitPrepBoundaryTest::isTrackedJavaSource)
          .sorted(Comparator.comparing(Path::toString))
          .toList();
    }
  }

  private static boolean isTrackedJavaSource(Path path) {
    String fileName = fileNameOrThrow(path);
    return fileName.endsWith(".java") && !fileName.startsWith("._");
  }

  private static Set<String> readAdapterImports(Path file) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .map(ADAPTER_IMPORT_PATTERN::matcher)
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
