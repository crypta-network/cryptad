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
class KernelTransportBoundaryTest {
  private static final Path KERNEL_TRANSPORT_MAIN_JAVA =
      Path.of("kernel-transport", "src", "main", "java");
  private static final Path KERNEL_TRANSPORT_ALLOWED_HOSTS =
      KERNEL_TRANSPORT_MAIN_JAVA.resolve(Path.of("network", "crypta", "io", "AllowedHosts.java"));
  private static final Path KERNEL_TRANSPORT_NETWORK_INTERFACE =
      KERNEL_TRANSPORT_MAIN_JAVA.resolve(
          Path.of("network", "crypta", "io", "NetworkInterface.java"));
  private static final Path KERNEL_TRANSPORT_IO_STATISTIC_COLLECTOR =
      KERNEL_TRANSPORT_MAIN_JAVA.resolve(
          Path.of("network", "crypta", "io", "comm", "IOStatisticCollector.java"));
  private static final Path KERNEL_TRANSPORT_PACKET_THROTTLE =
      KERNEL_TRANSPORT_MAIN_JAVA.resolve(
          Path.of("network", "crypta", "io", "xfer", "PacketThrottle.java"));
  private static final Path KERNEL_TRANSPORT_PARTIALLY_RECEIVED_BLOCK =
      KERNEL_TRANSPORT_MAIN_JAVA.resolve(
          Path.of("network", "crypta", "io", "xfer", "PartiallyReceivedBlock.java"));
  private static final Path RUNTIME_NODE_ALLOWED_HOSTS =
      Path.of(
          "runtime-node", "src", "main", "java", "network", "crypta", "io", "AllowedHosts.java");
  private static final Path RUNTIME_NODE_NETWORK_INTERFACE =
      Path.of(
          "runtime-node",
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "io",
          "NetworkInterface.java");
  private static final Path RUNTIME_NODE_IO_STATISTIC_COLLECTOR =
      Path.of(
          "runtime-node",
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "io",
          "comm",
          "IOStatisticCollector.java");
  private static final Path RUNTIME_NODE_PACKET_THROTTLE =
      Path.of(
          "runtime-node",
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "io",
          "xfer",
          "PacketThrottle.java");
  private static final Path RUNTIME_NODE_PARTIALLY_RECEIVED_BLOCK =
      Path.of(
          "runtime-node",
          "src",
          "main",
          "java",
          "network",
          "crypta",
          "io",
          "xfer",
          "PartiallyReceivedBlock.java");
  private static final Pattern FORBIDDEN_IMPORT_PATTERN =
      Pattern.compile(
          "^import(?:\\s+static)?\\s+"
              + "(network\\.crypta\\.(?:node|runtime|client)\\.[^;]+"
              + "|network\\.crypta\\.clients\\.[^;]+);$");

  @Test
  void kernelTransportMain_whenScanningImports_expectNoRuntimeClientOrAdapterImports()
      throws IOException {
    Path repoRoot = repoRoot();
    Path kernelTransportMain = repoRoot.resolve(KERNEL_TRANSPORT_MAIN_JAVA);
    List<String> violations = new ArrayList<>();

    assertTrue(
        Files.isDirectory(kernelTransportMain), "kernel-transport main Java tree must exist");

    for (Path sourceFile : findJavaSources(kernelTransportMain)) {
      Set<String> imports = readForbiddenImports(sourceFile);
      if (!imports.isEmpty()) {
        violations.add(repoRoot.relativize(sourceFile) + " -> " + String.join(", ", imports));
      }
    }

    assertTrue(
        violations.isEmpty(),
        "kernel-transport main sources must stay free of node/runtime/client and adapter imports."
            + System.lineSeparator()
            + String.join(System.lineSeparator(), violations));
  }

  @Test
  void kernelTransportPhaseOne_whenCheckingOwnership_expectMovedSourcesOwnedByKernelTransport()
      throws IOException {
    Path repoRoot = repoRoot();

    assertTrue(
        Files.isRegularFile(repoRoot.resolve(KERNEL_TRANSPORT_ALLOWED_HOSTS)),
        "kernel-transport must own network.crypta.io.AllowedHosts in phase 1");
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(KERNEL_TRANSPORT_NETWORK_INTERFACE)),
        "kernel-transport must own network.crypta.io.NetworkInterface in phase 1");
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(KERNEL_TRANSPORT_IO_STATISTIC_COLLECTOR)),
        "kernel-transport must own network.crypta.io.comm.IOStatisticCollector in phase 1");
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(KERNEL_TRANSPORT_PACKET_THROTTLE)),
        "kernel-transport must own network.crypta.io.xfer.PacketThrottle in phase 1");
    assertTrue(
        Files.isRegularFile(repoRoot.resolve(KERNEL_TRANSPORT_PARTIALLY_RECEIVED_BLOCK)),
        "kernel-transport must own network.crypta.io.xfer.PartiallyReceivedBlock in phase 1");

    assertTrue(
        !Files.exists(repoRoot.resolve(RUNTIME_NODE_ALLOWED_HOSTS)),
        "runtime-node must not retain network.crypta.io.AllowedHosts after phase-1 extraction");
    assertTrue(
        !Files.exists(repoRoot.resolve(RUNTIME_NODE_NETWORK_INTERFACE)),
        "runtime-node must not retain network.crypta.io.NetworkInterface after phase-1 extraction");
    assertTrue(
        !Files.exists(repoRoot.resolve(RUNTIME_NODE_IO_STATISTIC_COLLECTOR)),
        "runtime-node must not retain network.crypta.io.comm.IOStatisticCollector after phase-1"
            + " extraction");
    assertTrue(
        !Files.exists(repoRoot.resolve(RUNTIME_NODE_PACKET_THROTTLE)),
        "runtime-node must not retain network.crypta.io.xfer.PacketThrottle after phase-1"
            + " extraction");
    assertTrue(
        !Files.exists(repoRoot.resolve(RUNTIME_NODE_PARTIALLY_RECEIVED_BLOCK)),
        "runtime-node must not retain network.crypta.io.xfer.PartiallyReceivedBlock after phase-1"
            + " extraction");
  }

  private static List<Path> findJavaSources(Path root) throws IOException {
    try (Stream<Path> walk = Files.walk(root)) {
      return walk.filter(Files::isRegularFile)
          .filter(KernelTransportBoundaryTest::isTrackedJavaSource)
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
