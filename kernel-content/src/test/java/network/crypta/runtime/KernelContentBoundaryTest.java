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
  private static final Path KERNEL_CONTENT_CLIENT_PACKAGE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(Path.of("network", "crypta", "client"));
  private static final Path KERNEL_CONTENT_EVENTS_PACKAGE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(Path.of("network", "crypta", "client", "events"));
  private static final Path KERNEL_CONTENT_FILTER_PACKAGE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(Path.of("network", "crypta", "client", "filter"));
  private static final Path KERNEL_CONTENT_ASYNC_PACKAGE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(Path.of("network", "crypta", "client", "async"));
  private static final Path KERNEL_CONTENT_ALERTS_PACKAGE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(Path.of("network", "crypta", "client", "async", "alerts"));
  private static final Path KERNEL_CONTENT_PERSISTENCE_PACKAGE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(
          Path.of("network", "crypta", "client", "async", "persistence"));
  private static final Path KERNEL_CONTENT_SUPPORT_PACKAGE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(Path.of("network", "crypta", "support"));
  private static final Path KERNEL_CONTENT_SUPPORT_API_PACKAGE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(Path.of("network", "crypta", "support", "api"));
  private static final Path RUNTIME_NODE_CLIENT_PACKAGE =
      Path.of("runtime-node", "src", "main", "java", "network", "crypta", "client");
  private static final Path RUNTIME_NODE_EVENTS_PACKAGE =
      Path.of("runtime-node", "src", "main", "java", "network", "crypta", "client", "events");
  private static final Path RUNTIME_NODE_FILTER_PACKAGE =
      Path.of("runtime-node", "src", "main", "java", "network", "crypta", "client", "filter");
  private static final Path RUNTIME_NODE_ALERTS_PACKAGE =
      Path.of(
          "runtime-node", "src", "main", "java", "network", "crypta", "client", "async", "alerts");
  private static final Path RUNTIME_NODE_ASYNC_PACKAGE =
      Path.of("runtime-node", "src", "main", "java", "network", "crypta", "client", "async");
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
  private static final Path RUNTIME_NODE_SUPPORT_PACKAGE =
      Path.of("runtime-node", "src", "main", "java", "network", "crypta", "support");
  private static final Path RUNTIME_NODE_SUPPORT_API_PACKAGE =
      Path.of("runtime-node", "src", "main", "java", "network", "crypta", "support", "api");
  private static final Path KERNEL_CONTENT_MEDIA_TYPE =
      KERNEL_CONTENT_SUPPORT_PACKAGE.resolve("MediaType.java");
  private static final Path RUNTIME_NODE_MEDIA_TYPE =
      RUNTIME_NODE_SUPPORT_PACKAGE.resolve("MediaType.java");
  private static final List<String> MOVED_CLIENT_FAILURE_TYPES =
      List.of(
          "FailureCodeTracker.java",
          "FetchException.java",
          "InsertException.java",
          "MetadataResolutionTarget.java",
          "MetadataUnresolvedException.java");
  private static final List<String> MOVED_EVENT_TYPES =
      List.of(
          "ClientEventListener.java",
          "ClientEventProducer.java",
          "SimpleEventProducer.java",
          "EventLogger.java",
          "EventDumper.java",
          "SplitfileProgressEvent.java",
          "ClientEventDispatchContext.java",
          "ClientEventPersistentTask.java");
  private static final List<String> MOVED_FILTER_FAILURE_TYPES =
      List.of("DataFilterException.java", "UnsafeContentTypeException.java");
  private static final List<String> MOVED_ASYNC_UTILITY_TYPES =
      List.of(
          "BinaryBlob.java",
          "BinaryBlobFormatException.java",
          "BinaryBlobWriter.java",
          "BlockSet.java",
          "CacheFetchResult.java",
          "ClientGetterOptions.java",
          "ClientPutterOptions.java",
          "PersistenceDisabledException.java",
          "TooManyFilesInsertException.java");
  private static final List<String> MOVED_SUPPORT_MANIFEST_MODEL_TYPES =
      List.of("ContainerSizeEstimator.java");
  private static final List<String> MOVED_SUPPORT_API_MANIFEST_MODEL_TYPES =
      List.of("ManifestElement.java");
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
  void
      kernelContentPhaseTwo_whenCheckingSupportManifestModelOwnership_expectTypesOwnedByKernelContent()
          throws IOException {
    Path repoRoot = repoRoot();
    Path kernelContentSupportApi = repoRoot.resolve(KERNEL_CONTENT_SUPPORT_API_PACKAGE);

    assertTrue(
        Files.isRegularFile(kernelContentSupportApi.resolve("package-info.java")),
        "kernel-content support.api package must keep package-info.java");
    assertOwnedByKernelContent(
        repoRoot,
        KERNEL_CONTENT_SUPPORT_PACKAGE,
        RUNTIME_NODE_SUPPORT_PACKAGE,
        MOVED_SUPPORT_MANIFEST_MODEL_TYPES);
    assertOwnedByKernelContent(
        repoRoot,
        KERNEL_CONTENT_SUPPORT_API_PACKAGE,
        RUNTIME_NODE_SUPPORT_API_PACKAGE,
        MOVED_SUPPORT_API_MANIFEST_MODEL_TYPES);
  }

  @Test
  void
      kernelContentPhaseTwo_whenCheckingMovedLeafOwnership_expectLeafSafeTypesOwnedByKernelContent()
          throws IOException {
    Path repoRoot = repoRoot();
    Path kernelContentAsync = repoRoot.resolve(KERNEL_CONTENT_ASYNC_PACKAGE);

    assertOwnedByKernelContent(
        repoRoot,
        KERNEL_CONTENT_CLIENT_PACKAGE,
        RUNTIME_NODE_CLIENT_PACKAGE,
        MOVED_CLIENT_FAILURE_TYPES);
    assertOwnedByKernelContent(
        repoRoot,
        KERNEL_CONTENT_CLIENT_PACKAGE,
        RUNTIME_NODE_CLIENT_PACKAGE,
        List.of("InsertUriChecks.java"));
    assertOwnedByKernelContent(
        repoRoot, KERNEL_CONTENT_EVENTS_PACKAGE, RUNTIME_NODE_EVENTS_PACKAGE, MOVED_EVENT_TYPES);
    assertOwnedByKernelContent(
        repoRoot,
        KERNEL_CONTENT_FILTER_PACKAGE,
        RUNTIME_NODE_FILTER_PACKAGE,
        MOVED_FILTER_FAILURE_TYPES);
    assertTrue(
        Files.isDirectory(kernelContentAsync),
        "kernel-content must own leaf-safe sources under network.crypta.client.async");
    assertTrue(
        Files.isRegularFile(kernelContentAsync.resolve("package-info.java")),
        "kernel-content async package must keep package-info.java");
    assertOwnedByKernelContent(
        repoRoot,
        KERNEL_CONTENT_ASYNC_PACKAGE,
        RUNTIME_NODE_ASYNC_PACKAGE,
        MOVED_ASYNC_UTILITY_TYPES);
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
  void kernelContentPhaseTwo_whenScanningEventImports_expectNoClientContextImports()
      throws IOException {
    Path repoRoot = repoRoot();
    Path kernelContentEvents = repoRoot.resolve(KERNEL_CONTENT_EVENTS_PACKAGE);
    List<String> violations = new ArrayList<>();

    assertTrue(
        Files.isDirectory(kernelContentEvents),
        "kernel-content events package must exist before import scanning");

    for (Path sourceFile : findJavaSources(kernelContentEvents)) {
      Set<String> imports = readMatchingImports(sourceFile, CLIENT_CONTEXT_IMPORT_PATTERN);
      if (!imports.isEmpty()) {
        violations.add(repoRoot.relativize(sourceFile) + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "kernel-content event contracts must stay free of ClientContext imports."
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

  private static void assertOwnedByKernelContent(
      Path repoRoot, Path ownerPackage, Path formerOwnerPackage, List<String> fileNames) {
    for (String fileName : fileNames) {
      assertTrue(
          Files.isRegularFile(repoRoot.resolve(ownerPackage.resolve(fileName))),
          "kernel-content must own " + ownerPackage.resolve(fileName));
      assertFalse(
          Files.exists(repoRoot.resolve(formerOwnerPackage.resolve(fileName))),
          "runtime-node must not retain " + formerOwnerPackage.resolve(fileName));
    }
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
