package network.crypta.support.io;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import network.crypta.fs.AppEnv;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class LegacyFileSupportTest {

  @Test
  void operatingSystemNameKey_whenEnvVaries_expectLegacyNamesPreserved() {
    assertEquals(
        "WINDOWS", LegacyFileSupport.operatingSystemNameKey(new AppEnv(Map.of(), "Windows 11")));
    assertEquals("MAC_OS", LegacyFileSupport.operatingSystemNameKey(new AppEnv(Map.of(), "Mac")));
    assertEquals("LINUX", LegacyFileSupport.operatingSystemNameKey(new AppEnv(Map.of(), "Linux")));
    assertEquals(
        "FREE_BSD", LegacyFileSupport.operatingSystemNameKey(new AppEnv(Map.of(), "FreeBSD")));
    assertEquals(
        "GENERIC_UNIX", LegacyFileSupport.operatingSystemNameKey(new AppEnv(Map.of(), "Unix")));
  }

  @Test
  void sanitizeFileNameWithExtras_whenExtraCharsProvided_expectLegacySanitization() {
    String sanitized =
        LegacyFileSupport.sanitizeFileNameWithExtras(
            new AppEnv(Map.of(), "Linux"), "Alice\" Bob.fref", "\" ");

    assertEquals("Alice__Bob.fref", sanitized);
  }

  @Test
  void sanitizeFileNameWithExtras_whenWindowsReservedBasename_expectLegacyWindowsRules() {
    String sanitized =
        LegacyFileSupport.sanitizeFileNameWithExtras(
            new AppEnv(Map.of(), "Windows 11"), "con.txt", "");

    assertEquals("_con.txt", sanitized);
  }

  @Test
  void getCanonicalFile_whenDotSegmentsPresent_expectCanonicalPath(@TempDir Path tempDir)
      throws Exception {
    Path nested = Files.createDirectories(tempDir.resolve("nested"));
    Path dotted = nested.resolve("..").resolve("nested");

    assertEquals(nested.toRealPath().toFile(), LegacyFileSupport.getCanonicalFile(dotted.toFile()));
  }

  @Test
  void getLogTailReader_whenTruncated_expectStartsAtNextFullLine(@TempDir Path tempDir)
      throws Exception {
    Path log = tempDir.resolve("wrapper.log");
    Files.writeString(log, "line one\nline two\nline three\n");

    try (LineReadingInputStream input = LegacyFileSupport.getLogTailReader(log.toFile(), 12)) {
      assertEquals("line three", input.readLine(100000, 200, true));
      assertNull(input.readLine(100000, 200, true));
    }
  }

  @Test
  void getLogTailReader_whenWithinByteLimit_expectReadsFromStart(@TempDir Path tempDir)
      throws Exception {
    Path log = tempDir.resolve("wrapper.log");
    Files.writeString(log, "line one\nline two\n");

    try (LineReadingInputStream input = LegacyFileSupport.getLogTailReader(log.toFile(), 2000)) {
      assertEquals("line one", input.readLine(100000, 200, true));
      assertEquals("line two", input.readLine(100000, 200, true));
      assertNull(input.readLine(100000, 200, true));
    }
  }
}
