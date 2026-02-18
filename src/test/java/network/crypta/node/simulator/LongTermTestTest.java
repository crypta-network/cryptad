package network.crypta.node.simulator;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LongTermTestTest {

  private static final String STATUS_CSV_FILE_NAME = "status.csv";

  @TempDir Path tempDir;

  @Test
  void writeToStatusLog_whenFileDoesNotExist_createsFileWithDelimitedLine() throws IOException {
    // Arrange
    Path statusFile = tempDir.resolve(STATUS_CSV_FILE_NAME);
    File statusFileAsFile = statusFile.toFile();
    List<String> csvLine = List.of("a", "b", "c");

    // Act
    LongTermTest.writeToStatusLog(statusFileAsFile, csvLine);

    // Assert
    assertTrue(Files.exists(statusFile));
    assertEquals("a!b!c\n", readFileAsDefaultCharset(statusFile));
  }

  @Test
  void writeToStatusLog_whenCalledTwice_appendsSecondLine() throws IOException {
    // Arrange
    Path statusFile = tempDir.resolve(STATUS_CSV_FILE_NAME);
    File statusFileAsFile = statusFile.toFile();

    // Act
    LongTermTest.writeToStatusLog(statusFileAsFile, List.of("first"));
    LongTermTest.writeToStatusLog(statusFileAsFile, List.of("second", "line"));

    // Assert
    assertEquals("first\nsecond!line\n", readFileAsDefaultCharset(statusFile));
  }

  @Test
  void writeToStatusLog_whenCsvLineIsEmpty_writesEmptyLine() throws IOException {
    // Arrange
    Path statusFile = tempDir.resolve(STATUS_CSV_FILE_NAME);
    File statusFileAsFile = statusFile.toFile();

    // Act
    LongTermTest.writeToStatusLog(statusFileAsFile, List.of());

    // Assert
    assertEquals("\n", readFileAsDefaultCharset(statusFile));
  }

  @Test
  void writeToStatusLog_whenFileIsNull_throwsNullPointerException() {
    // Arrange
    List<String> csvLine = List.of("a");

    // Act + Assert
    assertThrows(NullPointerException.class, () -> LongTermTest.writeToStatusLog(null, csvLine));
  }

  @Test
  void writeToStatusLog_whenCsvLineIsNull_throwsNullPointerException() {
    // Arrange
    File statusFile = tempDir.resolve(STATUS_CSV_FILE_NAME).toFile();

    // Act + Assert
    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> LongTermTest.writeToStatusLog(statusFile, null));
  }

  @Test
  void writeToStatusLog_whenTargetIsDirectory_exitsWithExitThrewSomething()
      throws IOException, InterruptedException {
    // Arrange
    Path statusDirectory = Files.createDirectory(tempDir.resolve("statusDir"));
    Path logFile = tempDir.resolve("exit-harness.log");
    int expectedProcessExitCode = LongTermTest.EXIT_THREW_SOMETHING & 0xFF;

    ProcessBuilder processBuilder =
        new ProcessBuilder(
            javaExecutable().toString(),
            "-cp",
            System.getProperty("java.class.path"),
            ExitHarness.class.getName(),
            statusDirectory.toString());
    processBuilder.redirectErrorStream(true);
    processBuilder.redirectOutput(logFile.toFile());

    // Act
    Process process = processBuilder.start();
    boolean finished = process.waitFor(5, TimeUnit.SECONDS);

    // Assert
    assertTrue(finished);
    // Note: on Unix-like systems exit codes are truncated to 0..255.
    assertEquals(expectedProcessExitCode, process.exitValue());
    assertTrue(readFileAsDefaultCharset(logFile).contains("Exiting due to IOException "));
  }

  @Test
  void dateFormat_whenFormattingEpochMidnight_formatsAsGmtDate() {
    // Arrange
    Date epochMidnightUtc = Date.from(Instant.EPOCH);

    // Act
    String formatted = LongTermTest.dateFormat.format(epochMidnightUtc);

    // Assert
    assertEquals("1970.01.01", formatted);
  }

  @Test
  void today_whenInitialized_usesGmtTimeZone() {
    // Arrange + Act
    String timezoneId = LongTermTest.today.getTimeZone().getID();

    // Assert
    assertEquals("GMT", timezoneId);
    assertNotNull(LongTermTest.today.getTime());
  }

  private static String readFileAsDefaultCharset(Path path) throws IOException {
    return Files.readString(path, Charset.defaultCharset());
  }

  private static Path javaExecutable() {
    Path javaHome = Path.of(System.getProperty("java.home"));
    Path java = javaHome.resolve("bin").resolve("java");
    if (Files.exists(java)) {
      return java;
    }
    return javaHome.resolve("bin").resolve("java.exe");
  }

  static final class ExitHarness {
    public static void main(String[] args) {
      if (args.length != 1) {
        throw new IllegalArgumentException("Expected 1 argument: path");
      }
      File target = new File(args[0]);
      LongTermTest.writeToStatusLog(target, List.of("a"));
    }
  }
}
