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
class KernelRoutingBoundaryTest {
  private static final Path KERNEL_ROUTING_MAIN_JAVA =
      Path.of("kernel-routing", "src", "main", "java");
  private static final Path RUNTIME_NODE_MAIN_JAVA = Path.of("runtime-node", "src", "main", "java");
  private static final List<String> PHASE_ONE_MOVED_CLASSES =
      List.of(
          "BaseRequestThrottle",
          "BlockedTooLongException",
          "HighHtlAware",
          "InsertRoutingOptions",
          "LowLevelGetException",
          "LowLevelPutException",
          "NullSendableRequestItem",
          "OpennetDisabledException",
          "PeerStatusCounts",
          "PeerTooOldException",
          "RecentlyFailedReturn",
          "RequestClient",
          "RequestClientBuilder",
          "RequestCompletionListener",
          "RequestTransferOptions",
          "SecurityLevelListener",
          "SendableRequestItem",
          "SendableRequestItemKey");
  private static final Pattern FORBIDDEN_IMPORT_PATTERN =
      Pattern.compile(
          "^import(?:\\s+static)?\\s+"
              + "(network\\.crypta\\.(?:runtime|tools)\\.[^;]+"
              + "|network\\.crypta\\.io\\.comm\\.PeerContext"
              + "|network\\.crypta\\.node\\.(?:Node|PeerNode|RequestTracker|RequestSender|"
              + "RequestHandler|RequestTag|UIDTag));$");
  private static final Pattern FORBIDDEN_ADAPTER_IMPORT_PATTERN =
      Pattern.compile("^import(?:\\s+static)?\\s+(network\\.crypta\\.clients\\.[^;]+);$");

  @Test
  void kernelRoutingMain_whenScanningImports_expectNoRuntimeRootOrExecutionImports()
      throws IOException {
    Path repoRoot = repoRoot();
    Path kernelRoutingMain = repoRoot.resolve(KERNEL_ROUTING_MAIN_JAVA);
    List<String> violations = new ArrayList<>();

    assertTrue(Files.isDirectory(kernelRoutingMain), "kernel-routing main Java tree must exist");

    for (Path sourceFile : findJavaSources(kernelRoutingMain)) {
      Set<String> imports = readForbiddenImports(sourceFile, FORBIDDEN_IMPORT_PATTERN);
      if (!imports.isEmpty()) {
        violations.add(repoRoot.relativize(sourceFile) + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "kernel-routing main sources must stay free of runtime, tools, and runtime-owned node"
            + " execution imports."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void kernelRoutingMain_whenScanningImports_expectNoAdapterImports() throws IOException {
    Path repoRoot = repoRoot();
    Path kernelRoutingMain = repoRoot.resolve(KERNEL_ROUTING_MAIN_JAVA);
    List<String> violations = new ArrayList<>();

    for (Path sourceFile : findJavaSources(kernelRoutingMain)) {
      Set<String> imports = readForbiddenImports(sourceFile, FORBIDDEN_ADAPTER_IMPORT_PATTERN);
      if (!imports.isEmpty()) {
        violations.add(repoRoot.relativize(sourceFile) + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "kernel-routing main sources must stay free of adapter imports."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void kernelRoutingPhaseOne_whenCheckingOwnership_expectRepresentativeHelpersMoved()
      throws IOException {
    Path repoRoot = repoRoot();

    for (String className : PHASE_ONE_MOVED_CLASSES) {
      Path kernelRoutingSource =
          repoRoot.resolve(
              KERNEL_ROUTING_MAIN_JAVA.resolve(
                  Path.of("network", "crypta", "node", className + ".java")));
      Path runtimeNodeSource =
          repoRoot.resolve(
              RUNTIME_NODE_MAIN_JAVA.resolve(
                  Path.of("network", "crypta", "node", className + ".java")));

      assertTrue(
          Files.isRegularFile(kernelRoutingSource),
          "kernel-routing must own network.crypta.node." + className + " in phase 1");
      assertTrue(
          !Files.exists(runtimeNodeSource),
          "runtime-node must not retain network.crypta.node."
              + className
              + " after phase-1 extraction");
    }
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .filter(KernelRoutingBoundaryTest::isTrackedJavaSource)
          .sorted(Comparator.comparing(Path::toString))
          .toList();
    }
  }

  private static boolean isTrackedJavaSource(Path path) {
    String fileName = path.getFileName().toString();
    return fileName.endsWith(".java") && !fileName.startsWith("._");
  }

  private static Set<String> readForbiddenImports(Path file, Pattern pattern) throws IOException {
    try (Stream<String> lines = Files.lines(file)) {
      return lines
          .map(String::trim)
          .map(pattern::matcher)
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
