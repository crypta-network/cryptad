package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import network.crypta.fs.AppEnv;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
  void copy_whenLengthMinusOne_expectCopiesToEOF() throws Exception {
    byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    LegacyFileSupport.copy(new ByteArrayInputStream(data), out, -1);

    assertArrayEquals(data, out.toByteArray());
  }

  @Test
  void copy_whenExactLength_expectCopiesExactBytes() throws Exception {
    byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    LegacyFileSupport.copy(new ByteArrayInputStream(data), out, data.length);

    assertArrayEquals(data, out.toByteArray());
  }

  @Test
  void copy_whenLengthTooLarge_expectEofException() {
    byte[] data = {1, 2, 3};
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertThrows(
        EOFException.class, () -> LegacyFileSupport.copy(new ByteArrayInputStream(data), out, 10));
    assertArrayEquals(data, out.toByteArray());
  }

  @Test
  void createTempFile_whenPrefixShort_expectLegacyPadding(@TempDir Path tempDir) throws Exception {
    File temp = LegacyFileSupport.createTempFile("ab", ".txt", tempDir.toFile());

    assertTrue(temp.getName().startsWith("ab-TMP"));
    assertTrue(temp.exists());
  }

  @Test
  void createTempFile_whenDirectoryNull_expectCurrentWorkingDirectory() throws Exception {
    File temp = LegacyFileSupport.createTempFile("abc", ".txt", null);

    try {
      assertTrue(temp.exists());
      assertEquals(Path.of("").toRealPath().toFile(), temp.getParentFile().getCanonicalFile());
    } finally {
      Files.deleteIfExists(temp.toPath());
    }
  }

  @Test
  void readUTF_whenUtf8ContentPresent_expectDecodedText(@TempDir Path tempDir) throws Exception {
    Path file = tempDir.resolve("utf8.txt");
    String content = "abc\néé\nxyz";
    Files.writeString(file, content);

    assertEquals(content, LegacyFileSupport.readUTF(file.toFile()).toString());
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
