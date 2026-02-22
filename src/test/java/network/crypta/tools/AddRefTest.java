package network.crypta.tools;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import network.crypta.fs.AppEnv;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.LineReadingInputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class AddRefTest {

  private static final String USAGE_MESSAGE = "Please provide a file name as the first argument.";

  @TempDir Path tempDir;

  @Test
  void getMessage_whenInputIsEmpty_expectEmptyFieldSet() {
    LineReadingInputStream lis = new LineReadingInputStream(new ByteArrayInputStream(new byte[0]));

    SimpleFieldSet result = AddRef.getMessage(lis);

    assertNotNull(result);
    assertTrue(result.isEmpty());
  }

  @Test
  void getMessage_whenInputHasKeyValuePairs_expectParsedFieldSet() {
    String payload = "Foo=bar\nBaz=qux\nEndMessage\n";
    LineReadingInputStream lis =
        new LineReadingInputStream(
            new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)));

    SimpleFieldSet result = AddRef.getMessage(lis);

    assertEquals("bar", result.get("Foo"));
    assertEquals("qux", result.get("Baz"));
  }

  @Test
  void getMessage_whenLineHasNoEquals_expectStopsAndReturnsPreviouslyParsedFields() {
    String payload = "Foo=bar\nNoEqualsHere\nBaz=qux\nEndMessage\n";
    LineReadingInputStream lis =
        new LineReadingInputStream(
            new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)));

    SimpleFieldSet result = AddRef.getMessage(lis);

    assertEquals("bar", result.get("Foo"));
    assertNull(result.get("Baz"));
  }

  @Test
  void getMessage_whenLineStartsWithEnd_expectStopsBeforeParsingFurther() {
    String payload = "Foo=bar\nEndMessage\nBaz=qux\n";
    LineReadingInputStream lis =
        new LineReadingInputStream(
            new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8)));

    SimpleFieldSet result = AddRef.getMessage(lis);

    assertEquals("bar", result.get("Foo"));
    assertNull(result.get("Baz"));
  }

  @Test
  void getMessage_whenReadLineThrowsIOException_expectEmptyFieldSet() throws IOException {
    LineReadingInputStream lis = mock(LineReadingInputStream.class);
    when(lis.available()).thenReturn(1);
    doThrow(new IOException("boom")).when(lis).readLine(128, 128, true);

    SimpleFieldSet result = AddRef.getMessage(lis);

    assertNotNull(result);
    assertTrue(result.isEmpty());
    verify(lis, times(1)).readLine(128, 128, true);
  }

  @Test
  void main_whenNoArgs_expectExitCode255AndUsageMessageToStderr()
      throws IOException, InterruptedException {
    ProcessResult result = runAddRef();

    assertEquals(expectedInvalidArgumentExitCode(), result.exitCode());
    assertTrue(result.stderr().contains(USAGE_MESSAGE));
  }

  @Test
  void main_whenPathIsDirectory_expectExitCode255AndUsageMessageToStderr()
      throws IOException, InterruptedException {
    ProcessResult result = runAddRef(tempDir.toString());

    assertEquals(expectedInvalidArgumentExitCode(), result.exitCode());
    assertTrue(result.stderr().contains(USAGE_MESSAGE));
  }

  @Test
  void main_whenPathDoesNotExist_expectExitCode255AndUsageMessageToStderr()
      throws IOException, InterruptedException {
    ProcessResult result = runAddRef(tempDir.resolve("missing.ref").toString());

    assertEquals(expectedInvalidArgumentExitCode(), result.exitCode());
    assertTrue(result.stderr().contains(USAGE_MESSAGE));
  }

  private static int expectedInvalidArgumentExitCode() {
    // System.exit(-1) appears as -1 on Windows and 255 on POSIX-like systems.
    return new AppEnv().isWindows() ? -1 : 255;
  }

  private static ProcessResult runAddRef(String... args) throws IOException, InterruptedException {
    String javaBin =
        Path.of(System.getProperty("java.home")).resolve("bin").resolve("java").toString();

    List<String> cmd = new java.util.ArrayList<>();
    cmd.add(javaBin);
    cmd.add("-cp");
    cmd.add(System.getProperty("java.class.path"));
    cmd.add("network.crypta.tools.AddRef");
    cmd.addAll(List.of(args));

    Process process = new ProcessBuilder(cmd).start();

    boolean finished = process.waitFor(10, TimeUnit.SECONDS);
    if (!finished) {
      process.destroyForcibly();
      throw new IllegalStateException("AddRef process did not exit within timeout");
    }

    // Drain streams after the process exits; AddRef should only emit small amounts of output.
    process.getInputStream().readAllBytes();
    String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
    return new ProcessResult(process.exitValue(), stderr);
  }

  private record ProcessResult(int exitCode, String stderr) {}
}
