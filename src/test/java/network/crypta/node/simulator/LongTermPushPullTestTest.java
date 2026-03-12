package network.crypta.node.simulator;

import java.io.File;
import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LongTermPushPullTestTest {
  private static final int MAX_N = 8;

  @TempDir Path tempDir;

  @Test
  void dumpStats_whenValidCsvWithSuccessAndFailure_expectSummaryLines() throws Exception {
    // Arrange
    String uid = tempDir.resolve("longterm").toString();
    File csvFile = new File(uid + ".csv");
    String[] pushTimesForDay18 = zeroFilledTimes();
    pushTimesForDay18[2] = "FAILED_PUSH";
    String[] pushTimesForDay20 = zeroFilledTimes();
    pushTimesForDay20[1] = "1000";
    String[] pushTimesForDay21 = zeroFilledTimes();
    pushTimesForDay21[0] = "500";

    String[] pullTimesForDay21 = zeroFilledTimes();
    pullTimesForDay21[0] = "1200";
    pullTimesForDay21[1] = "1500";
    pullTimesForDay21[2] = "DATA_NOT_FOUND";

    List<String> lines =
        List.of(
            buildPushOnlyLine("2025.12.18", "10", pushTimesForDay18),
            buildPushOnlyLine("2025.12.20", "12", pushTimesForDay20),
            buildFullLine(pushTimesForDay21, pullTimesForDay21));
    Files.write(csvFile.toPath(), lines, StandardCharsets.UTF_8);

    CapturedOutput output = captureOutput();

    // Act
    try {
      invokeDumpStats(uid);
    } finally {
      output.restore();
    }

    // Assert
    String stdout = output.stdout();
    assertTrue(stdout.contains("Checking delta: 3 days"));
    assertTrue(stdout.contains("DATA_NOT_FOUND : 1"));
    assertTrue(stdout.contains("Insert failure: 1"));
    assertTrue(stdout.contains("No match: 1"));
  }

  @Test
  void dumpStats_whenInvalidDate_expectParseException() throws Exception {
    // Arrange
    String uid = tempDir.resolve("invalid").toString();
    File csvFile = new File(uid + ".csv");
    Files.writeString(csvFile.toPath(), "2025-12-21,1\n", StandardCharsets.UTF_8);

    // Act + Assert
    assertThrows(ParseException.class, () -> invokeDumpStats(uid));
  }

  private static String buildPushOnlyLine(String date, String seedTime, String[] pushTimes) {
    StringBuilder builder = new StringBuilder();
    builder.append(date).append(',').append(1).append(',').append(seedTime);
    for (String time : pushTimes) {
      builder.append(',').append(time);
    }
    return builder.toString();
  }

  private static String buildFullLine(String[] pushTimes, String[] pullTimes) {
    StringBuilder builder = new StringBuilder();
    builder.append(buildPushOnlyLine("2025.12.21", "14", pushTimes));
    builder.append(',').append("16");
    for (String time : pullTimes) {
      builder.append(',').append(time);
    }
    return builder.toString();
  }

  private static String[] zeroFilledTimes() {
    String[] times = new String[MAX_N + 1];
    Arrays.fill(times, "0");
    return times;
  }

  private static void invokeDumpStats(String uid)
      throws IOException, ParseException, ReflectiveOperationException {
    MethodHandles.Lookup lookup =
        MethodHandles.privateLookupIn(LongTermPushPullTest.class, MethodHandles.lookup());
    MethodHandle method =
        lookup.findStatic(
            LongTermPushPullTest.class,
            "dumpStats",
            MethodType.methodType(void.class, String.class));
    try {
      method.invoke(uid);
    } catch (Throwable e) {
      switch (e) {
        case IOException ioException -> throw ioException;
        case ParseException parseException -> throw parseException;
        case RuntimeException runtimeException -> throw runtimeException;
        case Error error -> throw error;
        default ->
            throw new ReflectiveOperationException("Unexpected exception invoking dumpStats", e);
      }
    }
  }

  private static CapturedOutput captureOutput() {
    return new CapturedOutput();
  }

  private static final class CapturedOutput {
    private final java.io.PrintStream originalOut;
    private final java.io.ByteArrayOutputStream buffer;

    @SuppressWarnings("java:S106")
    private CapturedOutput() {
      this.originalOut = System.out;
      this.buffer = new java.io.ByteArrayOutputStream();
      System.setOut(new java.io.PrintStream(buffer, true, StandardCharsets.UTF_8));
    }

    @SuppressWarnings("java:S106")
    private void restore() {
      System.setOut(originalOut);
    }

    private String stdout() {
      return buffer.toString(StandardCharsets.UTF_8);
    }
  }
}
