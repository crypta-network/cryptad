package network.crypta.node.simulator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import network.crypta.node.NodeInitException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SeednodePingTestTest {
  @Test
  void main_whenBaseDirIsFile_exitsWithTestErrorCode() throws Exception {
    Path sandboxRoot = Path.of("build", "test-sandboxes");
    Files.createDirectories(sandboxRoot);
    Path workingDir = Files.createTempDirectory(sandboxRoot, "seednode-pingtest-");
    Files.writeString(workingDir.resolve("seednode-pingtest"), "block directory creation");

    ProcessResult result = runSeednodePingTest(workingDir.toFile());

    assertEquals(NodeInitException.EXIT_TEST_ERROR, result.exitCode());
  }

  @Test
  void statusDir_whenClassLoaded_usesDefaultPath() {
    File statusDir = SeednodePingTest.statusDir;
    assertEquals("status", statusDir.getName());
    File parent = statusDir.getParentFile();
    assertEquals("seednodes", parent == null ? null : parent.getName());
  }

  @Test
  void waitForProcess_whenProcessExits_returnsExitCodeAndOutput() throws Exception {
    Process process = Mockito.mock(Process.class);
    Mockito.when(process.waitFor(Mockito.anyLong(), Mockito.any(TimeUnit.class))).thenReturn(true);
    Mockito.when(process.exitValue()).thenReturn(7);
    Mockito.when(process.getInputStream())
        .thenReturn(new ByteArrayInputStream("ok".getBytes(StandardCharsets.UTF_8)));

    ProcessResult result = waitForProcess(process, 1);

    assertEquals(7, result.exitCode());
    assertEquals("ok", result.output());
  }

  private static ProcessResult runSeednodePingTest(File workingDir)
      throws IOException, InterruptedException {
    List<String> command = new ArrayList<>();
    command.add(javaBinPath());
    command.add("-cp");
    command.add(System.getProperty("java.class.path"));
    command.add(SeednodePingTest.class.getName());

    ProcessBuilder processBuilder = new ProcessBuilder(command);
    processBuilder.directory(workingDir);
    processBuilder.redirectErrorStream(true);
    Process process = processBuilder.start();
    return waitForProcess(process, 30);
  }

  private static ProcessResult waitForProcess(Process process, long timeoutSeconds)
      throws IOException, InterruptedException {
    boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
    if (!finished) {
      process.destroyForcibly();
      throw new IllegalStateException("SeednodePingTest process did not exit in time");
    }
    String output =
        new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
    return new ProcessResult(process.exitValue(), output);
  }

  private static String javaBinPath() {
    String javaHome = System.getProperty("java.home");
    return javaHome + File.separator + "bin" + File.separator + "java";
  }

  private record ProcessResult(int exitCode, String output) {}
}
