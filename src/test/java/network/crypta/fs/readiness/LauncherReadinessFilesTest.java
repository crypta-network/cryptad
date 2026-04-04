package network.crypta.fs.readiness;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LauncherReadinessFilesTest {

  @TempDir Path tempDir;

  @Test
  void writeAndRead_whenReadyPayload_expectRoundTrip() throws Exception {
    Path readinessFile = LauncherReadinessFiles.resolve(tempDir);
    LauncherReadinessInfo expected =
        new LauncherReadinessInfo(
            LauncherReadinessInfo.VERSION_1, LauncherReadinessInfo.READY_STATE, 8888, "/");

    LauncherReadinessFiles.write(readinessFile, expected);

    LauncherReadinessInfo actual = LauncherReadinessFiles.read(readinessFile).orElseThrow();
    assertEquals(expected, actual);
    assertTrue(actual.isReady());
    var snapshot = LauncherReadinessFiles.readSnapshot(readinessFile).orElseThrow();
    assertEquals(expected, snapshot.info());
  }

  @Test
  void read_whenVersionUnsupported_returnsEmpty() throws Exception {
    Path readinessFile = LauncherReadinessFiles.resolve(tempDir);
    Files.writeString(
        readinessFile,
        """
        version=2
        state=ready
        ui.port=8888
        ui.root=/
        """);

    assertFalse(LauncherReadinessFiles.read(readinessFile).isPresent());
  }

  @Test
  void read_whenUiRootMissing_expectDefaultRoot() throws Exception {
    Path readinessFile = LauncherReadinessFiles.resolve(tempDir);
    Files.writeString(
        readinessFile,
        """
        version=1
        state=ready
        ui.port=8888
        """);

    LauncherReadinessInfo actual = LauncherReadinessFiles.read(readinessFile).orElseThrow();

    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, actual.uiRoot());
    assertTrue(actual.isReady());
  }

  @Test
  void clear_whenReadinessAndTempFileExist_expectBothDeleted() throws Exception {
    Path readinessFile = LauncherReadinessFiles.resolve(tempDir);
    Path tempFile = readinessFile.resolveSibling(readinessFile.getFileName() + ".tmp");
    LauncherReadinessFiles.write(readinessFile, LauncherReadinessInfo.ready(8888));
    Files.writeString(tempFile, "stale");

    LauncherReadinessFiles.clear(readinessFile);

    assertFalse(Files.exists(readinessFile));
    assertFalse(Files.exists(tempFile));
  }
}
