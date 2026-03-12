package network.crypta.node.simulator;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.crypt.RandomSource;
import network.crypta.node.NodeStarter;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.slf4j.event.Level;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Answers.CALLS_REAL_METHODS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;

@SuppressWarnings("java:S100")
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(Resources.SYSTEM_OUT)
@ResourceLock(Resources.SYSTEM_ERR)
class BootstrapSeedTestTest {

  private static final String OUTPUT_PREFIX = "Output:\n";

  @TempDir Path tempDir;

  @Test
  void main_whenSeednodesFileMissing_expectExitNoSeednodes() {
    SubprocessResult result =
        assertTimeoutPreemptively(
            Duration.ofSeconds(15), () -> runBootstrapSeedTestInSubprocess(tempDir, "missing"));

    assertEquals(
        expectedProcessExitCode(BootstrapSeedTest.EXIT_NO_SEEDNODES),
        result.exitCode(),
        () -> OUTPUT_PREFIX + result.output());
    assertTrue(
        result.output().contains("Unable to read seednodes.fref"),
        () -> OUTPUT_PREFIX + result.output());
  }

  @Test
  void main_whenSeednodesFileEmpty_expectExitNoSeednodes() {
    SubprocessResult result =
        assertTimeoutPreemptively(
            Duration.ofSeconds(15), () -> runBootstrapSeedTestInSubprocess(tempDir, "empty"));

    assertEquals(
        expectedProcessExitCode(BootstrapSeedTest.EXIT_NO_SEEDNODES),
        result.exitCode(),
        () -> OUTPUT_PREFIX + result.output());
    assertTrue(
        result.output().contains("Unable to read seednodes.fref"),
        () -> OUTPUT_PREFIX + result.output());
  }

  @Test
  void main_whenGlobalTestInitThrows_expectExitThrewSomething() {
    SubprocessResult result =
        assertTimeoutPreemptively(
            Duration.ofSeconds(15), () -> runBootstrapSeedTestInSubprocess(tempDir, "throw-init"));

    assertEquals(
        expectedProcessExitCode(BootstrapSeedTest.EXIT_THREW_SOMETHING),
        result.exitCode(),
        () -> OUTPUT_PREFIX + result.output());
    assertTrue(result.output().contains("CAUGHT:"), () -> OUTPUT_PREFIX + result.output());
    assertTrue(
        result.output().contains("globalTestInit failed on purpose"),
        () -> OUTPUT_PREFIX + result.output());
  }

  @Test
  void constants_whenReferenced_expectStableValues() {
    assertEquals(257, BootstrapSeedTest.EXIT_NO_SEEDNODES);
    assertEquals(258, BootstrapSeedTest.EXIT_FAILED_TARGET);
    assertEquals(259, BootstrapSeedTest.EXIT_THREW_SOMETHING);
    assertEquals(5006, BootstrapSeedTest.DARKNET_PORT);
    assertEquals(5007, BootstrapSeedTest.OPENNET_PORT);
  }

  private static SubprocessResult runBootstrapSeedTestInSubprocess(Path dir, String mode)
      throws IOException, InterruptedException {
    List<String> command = new ArrayList<>();
    command.add(javaBinaryPath());
    command.add("-cp");
    command.add(System.getProperty("java.class.path"));
    command.add(BootstrapSeedTestRunner.class.getName());
    command.add(mode);

    ProcessBuilder pb =
        new ProcessBuilder(command).redirectErrorStream(true).directory(dir.toFile());
    Process process = pb.start();

    ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
    AtomicReference<Throwable> outputError = new AtomicReference<>();
    Thread outputReader =
        new Thread(
            () -> {
              try (InputStream is = process.getInputStream()) {
                is.transferTo(outputBuffer);
              } catch (IOException e) {
                outputError.set(e);
              }
            },
            "BootstrapSeedTestTest-output");
    outputReader.setDaemon(true);
    outputReader.start();

    boolean finished = process.waitFor(10, TimeUnit.SECONDS);
    if (!finished) {
      process.destroyForcibly();
      throw new IOException(
          "BootstrapSeedTest subprocess did not exit in time: " + String.join(" ", command));
    }
    outputReader.join(Duration.ofSeconds(2).toMillis());
    if (outputError.get() != null) {
      throw new IOException("Failed reading subprocess output", outputError.get());
    }

    int exitCode = process.exitValue();
    String output = outputBuffer.toString(StandardCharsets.UTF_8);
    return new SubprocessResult(exitCode, output, command);
  }

  private static int expectedProcessExitCode(int javaExitCode) {
    String osName = System.getProperty("os.name");
    if (osName == null) {
      return javaExitCode & 0xFF;
    }
    String normalized = osName.toLowerCase(Locale.ROOT);
    if (normalized.contains("win")) {
      return javaExitCode;
    }
    // POSIX process exit codes are 8-bit; System.exit(>255) wraps.
    return javaExitCode & 0xFF;
  }

  private static String javaBinaryPath() {
    String javaHome = System.getProperty("java.home");
    return Path.of(javaHome, "bin", "java").toString();
  }

  private record SubprocessResult(int exitCode, String output, List<String> command) {
    private SubprocessResult {
      command = List.copyOf(command);
    }

    @Override
    public @NonNull String toString() {
      return "exitCode="
          + exitCode
          + "\nCommand: "
          + String.join(" ", command)
          + "\nOutput:\n"
          + output;
    }
  }

  /**
   * Subprocess entrypoint used by {@link #runBootstrapSeedTestInSubprocess(Path, String)}.
   *
   * <p>This is required because {@link System#exit(int)} cannot be intercepted in-process on this
   * runtime (Security Manager is disabled).
   */
  public static final class BootstrapSeedTestRunner {
    public static void main(String[] args) throws Exception {
      if (args.length != 1) {
        throw new IllegalArgumentException("Expected args: <mode>");
      }
      String mode = args[0];

      if ("missing".equals(mode)) {
        runMissingSeednodes();
        return;
      }
      if ("empty".equals(mode)) {
        runEmptySeednodes();
        return;
      }
      if ("throw-init".equals(mode)) {
        runThrowingGlobalTestInit();
        return;
      }

      throw new IllegalArgumentException("Unknown mode: " + mode);
    }

    private static void runMissingSeednodes() throws Exception {
      try (MockedStatic<NodeStarter> nodeStarter =
          Mockito.mockStatic(NodeStarter.class, CALLS_REAL_METHODS)) {
        nodeStarter
            .when(
                () ->
                    NodeStarter.globalTestInit(
                        any(File.class),
                        anyBoolean(),
                        any(Level.class),
                        anyString(),
                        anyBoolean(),
                        isNull()))
            .thenReturn(mock(RandomSource.class));
        BootstrapSeedTest.main(new String[0]);
      }
    }

    private static void runEmptySeednodes() throws Exception {
      Files.write(Path.of("seednodes.fref"), new byte[0]);
      try (MockedStatic<NodeStarter> nodeStarter =
          Mockito.mockStatic(NodeStarter.class, CALLS_REAL_METHODS)) {
        nodeStarter
            .when(
                () ->
                    NodeStarter.globalTestInit(
                        any(File.class),
                        anyBoolean(),
                        any(Level.class),
                        anyString(),
                        anyBoolean(),
                        isNull()))
            .thenReturn(mock(RandomSource.class));
        BootstrapSeedTest.main(new String[0]);
      }
    }

    private static void runThrowingGlobalTestInit() throws Exception {
      try (MockedStatic<NodeStarter> nodeStarter =
          Mockito.mockStatic(NodeStarter.class, CALLS_REAL_METHODS)) {
        nodeStarter
            .when(
                () ->
                    NodeStarter.globalTestInit(
                        any(File.class),
                        anyBoolean(),
                        any(Level.class),
                        anyString(),
                        anyBoolean(),
                        isNull()))
            .thenThrow(new RuntimeException("globalTestInit failed on purpose"));
        BootstrapSeedTest.main(new String[0]);
      }
    }
  }
}
