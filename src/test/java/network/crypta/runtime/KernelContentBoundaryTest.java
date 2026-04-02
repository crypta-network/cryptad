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

import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class KernelContentBoundaryTest {
  private static final Path KERNEL_CONTENT_MAIN_JAVA =
      Path.of("kernel-content", "src", "main", "java");
  private static final Path KERNEL_CONTENT_ALERTS_PACKAGE =
      KERNEL_CONTENT_MAIN_JAVA.resolve(Path.of("network", "crypta", "client", "async", "alerts"));
  private static final Path RUNTIME_NODE_ALERTS_PACKAGE =
      Path.of(
          "runtime-node", "src", "main", "java", "network", "crypta", "client", "async", "alerts");
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
  void kernelContentPhaseOne_whenCheckingSupportOwnership_expectMediaTypeOwnedByKernelContent()
      throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isRegularFile(repoRoot.resolve(KERNEL_CONTENT_MEDIA_TYPE)),
        "kernel-content must own network.crypta.support.MediaType for the MIME helper cluster");
    assertTrue(
        !Files.exists(repoRoot.resolve(RUNTIME_NODE_MEDIA_TYPE)),
        "runtime-node must not retain network.crypta.support.MediaType after extraction");
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
    String fileName = path.getFileName().toString();
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

  private static Path repoRoot() throws IOException {
    Path repoRoot = Path.of("").toAbsolutePath().normalize();
    assertTrue(Files.isRegularFile(repoRoot.resolve("settings.gradle.kts")));
    return repoRoot.toRealPath();
  }
}
