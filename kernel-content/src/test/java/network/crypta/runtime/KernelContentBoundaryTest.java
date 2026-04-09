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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class KernelContentBoundaryTest {
  private static final Path KERNEL_CONTENT_MAIN_JAVA =
      Path.of("kernel-content", "src", "main", "java");
  private static final Path KERNEL_CONTENT_ALERTS_PACKAGE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(Path.of("network", "crypta", "client", "async", "alerts"));
  private static final Path KERNEL_CONTENT_PERSISTENCE_PACKAGE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(
          Path.of("network", "crypta", "client", "async", "persistence"));
  private static final Path RUNTIME_NODE_ALERTS_PACKAGE =
      Path.of(
          "runtime-node", "src", "main", "java", "network", "crypta", "client", "async", "alerts");
  private static final Path RUNTIME_NODE_PERSISTENCE_PACKAGE =
      Path.of(
          "runtime-node",
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "client",
          "async",
          "persistence");
  private static final Path KERNEL_CONTENT_MEDIA_TYPE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(Path.of("network", "crypta", "support", "MediaType.java"));
  private static final Path RUNTIME_NODE_MEDIA_TYPE =
      Path.of(
          "runtime-node", "src", "main", "java", "network", "crypta", "support", "MediaType.java");
  private static final Pattern FORBIDDEN_IMPORT_PATTERN =
      Pattern.compile(
          "^import(?:\\s+static)?\\s+"
              + "(network\\.crypta\\.(?:node|runtime|io)\\.[^;]+"
              + "|network\\.crypta\\.clients\\.(?:fcp|http)\\.[^;]+);$");
  private static final Pattern CLIENT_CONTEXT_IMPORT_PATTERN =
      Pattern.compile(
          "^import(?:\\s+static)?\\s+(network\\.crypta\\.client\\.async\\.ClientContext);$");

  @Test
  void kernelContentMain_whenScanningImports_expectNoRuntimeOrAdapterImports() throws IOException {
    Path repoRoot = repoRoot();
    Path kernelContentMain = repoRoot.resolve(KERNEL_CONTENT_MAIN_JAVA);
    List<String> violations = new ArrayList<>();

    assertTrue(Files.isDirectory(kernelContentMain), "kernel-content main Java tree must exist");

    for (Path sourceFile : findJavaSources(kernelContentMain)) {
      Set<String> imports = readForbiddenImports(sourceFile);
      if (!imports.isEmpty()) {
        violations.add(repoRoot.relativize(sourceFile) + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "kernel-content main sources must stay free of network/node/runtime/io and adapter imports."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void kernelContentPhaseOne_whenCheckingWholePackageMoves_expectAlertsOwnedByKernelContent()
      throws IOException {
    Path repoRoot = repoRoot();
    Path kernelContentAlerts = repoRoot.resolve(KERNEL_CONTENT_ALERTS_PACKAGE);
    Path runtimeNodeAlerts = repoRoot.resolve(RUNTIME_NODE_ALERTS_PACKAGE);

    assertTrue(
        Files.isDirectory(kernelContentAlerts),
        "kernel-content must own network.crypta.client.async.alerts in phase 1");
    assertTrue(
        Files.isRegularFile(kernelContentAlerts.resolve("package-info.java")),
        "kernel-content async.alerts package must keep package-info.java");
    assertTrue(
        !Files.isDirectory(runtimeNodeAlerts) || findJavaSources(runtimeNodeAlerts).isEmpty(),
        "runtime-node must not retain any network.crypta.client.async.alerts Java sources after"
            + " extraction");
  }

  @Test
  void kernelContentPhaseTwo_whenCheckingWholePackageMoves_expectPersistenceOwnedByKernelContent()
      throws IOException {
    Path repoRoot = repoRoot();
    Path kernelContentPersistence = repoRoot.resolve(KERNEL_CONTENT_PERSISTENCE_PACKAGE);
    Path runtimeNodePersistence = repoRoot.resolve(RUNTIME_NODE_PERSISTENCE_PACKAGE);

    assertTrue(
        Files.isDirectory(kernelContentPersistence),
        "kernel-content must own network.crypta.client.async.persistence");
    assertTrue(
        Files.isRegularFile(kernelContentPersistence.resolve("package-info.java")),
        "kernel-content async.persistence package must keep package-info.java");
    assertTrue(
        Files.isRegularFile(
            kernelContentPersistence.resolve("PersistentRequestRuntimeContext.java")),
        "kernel-content async.persistence package must declare the runtime-context seam");
    assertTrue(
        !Files.isDirectory(runtimeNodePersistence)
            || findJavaSources(runtimeNodePersistence).isEmpty(),
        "runtime-node must not retain any network.crypta.client.async.persistence Java sources"
            + " after extraction");
  }

  @Test
  void kernelContentPhaseOne_whenCheckingSupportOwnership_expectMediaTypeOwnedByKernelContent()
      throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isRegularFile(repoRoot.resolve(KERNEL_CONTENT_MEDIA_TYPE)),
        "kernel-content must own network.crypta.support.MediaType for the MIME helper cluster");
    assertFalse(
        Files.exists(repoRoot.resolve(RUNTIME_NODE_MEDIA_TYPE)),
        "runtime-node must not retain network.crypta.support.MediaType after extraction");
  }

  @Test
  void kernelContentPhaseTwo_whenScanningPersistenceImports_expectNoClientContextImports()
      throws IOException {
    Path repoRoot = repoRoot();
    Path kernelContentPersistence = repoRoot.resolve(KERNEL_CONTENT_PERSISTENCE_PACKAGE);
    List<String> violations = new ArrayList<>();

    assertTrue(
        Files.isDirectory(kernelContentPersistence),
        "kernel-content persistence package must exist before import scanning");

    for (Path sourceFile : findJavaSources(kernelContentPersistence)) {
      Set<String> imports = readMatchingImports(sourceFile, CLIENT_CONTEXT_IMPORT_PATTERN);
      if (!imports.isEmpty()) {
        violations.add(repoRoot.relativize(sourceFile) + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "kernel-content persistence contracts must stay free of ClientContext imports."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void kernelContentMain_whenScanningProductionPackages_expectPackageInfoInEveryPackage()
      throws IOException {
    Path repoRoot = repoRoot();
    Path kernelContentMain = repoRoot.resolve(KERNEL_CONTENT_MAIN_JAVA);
    Set<Path> productionPackages = new TreeSet<>(Comparator.comparing(Path::toString));
    List<String> missingPackageInfos = new ArrayList<>();

    assertTrue(Files.isDirectory(kernelContentMain), "kernel-content main Java tree must exist");

    for (Path sourceFile : findJavaSources(kernelContentMain)) {
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
        "Every :kernel-content main package with production Java files must declare "
            + "package-info.java."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), missingPackageInfos));
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .filter(KernelContentBoundaryTest::isTrackedJavaSource)
          .sorted(Comparator.comparing(Path::toString))
          .toList();
    }
  }

  private static boolean isTrackedJavaSource(Path path) {
    String fileName = fileNameOrThrow(path);
    return fileName.endsWith(".java") && !fileName.startsWith("._");
  }

  private static Set<String> readForbiddenImports(Path file) throws IOException {
    return readMatchingImports(file, FORBIDDEN_IMPORT_PATTERN);
  }

  private static Set<String> readMatchingImports(Path file, Pattern pattern) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .map(pattern::matcher)
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
