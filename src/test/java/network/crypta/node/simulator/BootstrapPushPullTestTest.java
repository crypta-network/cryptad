package network.crypta.node.simulator;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class BootstrapPushPullTestTest {

  private static final String MAIN_CLASS = "network.crypta.node.simulator.BootstrapPushPullTest";
  private static final String SEEDNODES_ERROR_SUBSTRING = "Unable to read seednodes.fref";
  private static final String STDERR_MISSING_SEEDNODES_PREFIX =
      "Expected stderr to mention missing seednodes. stderr=";

  private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

  @Test
  void main_whenSeednodesMissing_expectExitNoSeednodesAndMessage(@TempDir Path tempDir)
      throws Exception {
    // Arrange
    // No seednodes.fref present.

    // Act
    ProcessResult result = runMain(tempDir, List.of());

    // Assert
    assertExitNoSeednodes(result);
    assertTrue(
        result.stderr.contains(SEEDNODES_ERROR_SUBSTRING),
        () -> STDERR_MISSING_SEEDNODES_PREFIX + result.stderr);
    assertTrue(
        Files.isDirectory(tempDir.resolve("bootstrap-push-pull-test")),
        "Expected the simulator to create its working directory before failing.");
  }

  @Test
  void main_whenSeednodesEmpty_expectExitNoSeednodesAndRemovesPriorWorkDir(@TempDir Path tempDir)
      throws Exception {
    // Arrange
    Path previousWorkDir = tempDir.resolve("bootstrap-push-pull-test");
    Files.createDirectories(previousWorkDir);
    Path sentinel = previousWorkDir.resolve("sentinel.txt");
    Files.writeString(sentinel, "old", StandardCharsets.UTF_8);

    Files.write(tempDir.resolve("seednodes.fref"), new byte[0]);

    // Act
    ProcessResult result = runMain(tempDir, List.of());

    // Assert
    assertExitNoSeednodes(result);
    assertFalse(
        Files.exists(sentinel), "Expected the simulator to clean its work directory at startup.");
    assertTrue(
        result.stderr.contains(SEEDNODES_ERROR_SUBSTRING),
        () -> "Expected stderr to mention empty seednodes. stderr=" + result.stderr);
  }

  @Test
  void main_whenIpOverrideProvided_expectStillExitNoSeednodes(@TempDir Path tempDir)
      throws Exception {
    // Arrange
    String ipOverride = "192.0.2.123"; // TEST-NET-1 (non-routable).

    // Act
    ProcessResult result = runMain(tempDir, List.of(ipOverride));

    // Assert
    assertExitNoSeednodes(result);
    assertTrue(
        result.stderr.contains(SEEDNODES_ERROR_SUBSTRING),
        () -> STDERR_MISSING_SEEDNODES_PREFIX + result.stderr);
  }

  @Test
  void main_whenExtraArgsProvided_expectStillExitNoSeednodes(@TempDir Path tempDir)
      throws Exception {
    // Arrange
    List<String> args = List.of("203.0.113.7", "ignored-arg"); // TEST-NET-3 (non-routable).

    // Act
    ProcessResult result = runMain(tempDir, args);

    // Assert
    assertExitNoSeednodes(result);
    assertTrue(
        result.stderr.contains(SEEDNODES_ERROR_SUBSTRING),
        () -> STDERR_MISSING_SEEDNODES_PREFIX + result.stderr);
  }

  @Test
  void exitCodes_whenCompared_expectDistinctValues() {
    // Arrange
    int[] codes = {
      BootstrapPushPullTest.EXIT_NO_SEEDNODES,
      BootstrapPushPullTest.EXIT_FAILED_TARGET,
      BootstrapPushPullTest.EXIT_INSERT_FAILED,
      BootstrapPushPullTest.EXIT_FETCH_FAILED,
      BootstrapPushPullTest.EXIT_THREW_SOMETHING
    };

    // Act / Assert
    for (int i = 0; i < codes.length; i++) {
      int left = codes[i];
      for (int j = i + 1; j < codes.length; j++) {
        int right = codes[j];
        assertNotEquals(
            left,
            right,
            () -> "Exit codes must be distinct to keep failures diagnosable; duplicate=" + left);
      }
    }
  }

  private static ProcessResult runMain(Path workingDir, List<String> args)
      throws IOException, InterruptedException {
    List<String> command = new ArrayList<>();
    command.add(javaExecutable().toString());
    command.add("-cp");
    command.add(buildProcessClasspath());
    command.add(MAIN_CLASS);
    command.addAll(args);

    ProcessBuilder processBuilder = new ProcessBuilder(command);
    processBuilder.directory(workingDir.toFile());

    Process process = processBuilder.start();

    boolean finished = process.waitFor(DEFAULT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    if (!finished) {
      process.destroyForcibly();
      throw new AssertionError("Process did not finish within " + DEFAULT_TIMEOUT);
    }

    String stdout = readUtf8(process.getInputStream().readAllBytes());
    String stderr = readUtf8(process.getErrorStream().readAllBytes());

    return new ProcessResult(process.exitValue(), stdout, stderr);
  }

  private static void assertExitNoSeednodes(ProcessResult result) {
    int expectedOsExitCode = Math.floorMod(BootstrapPushPullTest.EXIT_NO_SEEDNODES, 256);
    assertEquals(
        expectedOsExitCode,
        result.exitCode,
        () ->
            "Unexpected exit code.\n"
                + "expected (raw constant): "
                + BootstrapPushPullTest.EXIT_NO_SEEDNODES
                + "\n"
                + "expected (process exit code): "
                + expectedOsExitCode
                + "\n"
                + "actual (process exit code): "
                + result.exitCode
                + "\n"
                + "stdout:\n"
                + result.stdout
                + "\n"
                + "stderr:\n"
                + result.stderr);
  }

  private static String buildProcessClasspath() {
    String existingClasspath = System.getProperty("java.class.path");
    Path projectRoot = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();

    List<Path> extraEntries =
        List.of(
            projectRoot.resolve("build/classes/java/main"),
            projectRoot.resolve("build/classes/kotlin/main"),
            projectRoot.resolve("build/resources/main"),
            projectRoot.resolve("build/classes/java/test"),
            projectRoot.resolve("build/classes/kotlin/test"),
            projectRoot.resolve("build/resources/test"));

    List<String> entries = new ArrayList<>();
    for (Path entry : extraEntries) {
      if (Files.isDirectory(entry)) {
        entries.add(entry.toString());
      }
    }
    entries.add(existingClasspath);

    return String.join(File.pathSeparator, entries);
  }

  private static Path javaExecutable() {
    return Path.of(System.getProperty("java.home"), "bin", "java");
  }

  private static String readUtf8(byte[] bytes) {
    return new String(bytes, StandardCharsets.UTF_8);
  }

  private record ProcessResult(int exitCode, String stdout, String stderr) {}
}
