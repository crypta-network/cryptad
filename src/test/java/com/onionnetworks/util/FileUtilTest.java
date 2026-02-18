package com.onionnetworks.util;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class FileUtilTest {

  private String originalUserHome;

  @BeforeEach
  void rememberUserHome() {
    originalUserHome = System.getProperty("user.home");
  }

  @AfterEach
  void restoreUserHome() {
    if (originalUserHome != null) {
      System.setProperty("user.home", originalUserHome);
    } else {
      System.clearProperty("user.home");
    }
  }

  // sanitizeFileName --------------------------------------------------------------------------

  @Test
  @DisplayName("sanitizeFileName_whenUnsafeCharacters_expectStrippedAndDotsCollapsed")
  void sanitizeFileName_whenUnsafeCharacters_expectStrippedAndDotsCollapsed() {
    // Arrange
    String input = "a..b/c?d";

    // Act
    String sanitized = FileUtil.sanitizeFileName(input);

    // Assert
    assertEquals("a.bcd", sanitized);
  }

  @Test
  @DisplayName("sanitizeFileName_whenNoSafeCharacters_expectEmptyString")
  void sanitizeFileName_whenNoSafeCharacters_expectEmptyString() {
    // Arrange
    String input = "<>*";

    // Act
    String sanitized = FileUtil.sanitizeFileName(input);

    // Assert
    assertEquals("", sanitized);
  }

  // pickSafeFileName --------------------------------------------------------------------------

  @Test
  @DisplayName("pickSafeFileName_whenSanitizedEmpty_expectIndexHtml")
  void pickSafeFileName_whenSanitizedEmpty_expectIndexHtml() throws Exception {
    // Arrange
    URL url = new URI("http", "example.com", "/", null).toURL();

    // Act
    String name = FileUtil.pickSafeFileName(url);

    // Assert
    assertEquals("index.html", name);
  }

  @Test
  @DisplayName("pickSafeFileName_whenValidName_expectSanitizedName")
  void pickSafeFileName_whenValidName_expectSanitizedName() throws Exception {
    // Arrange
    URL url = new URI("http", "example.com", "/some-file.txt", null).toURL();

    // Act
    String name = FileUtil.pickSafeFileName(url);

    // Assert
    assertEquals("some-file.txt", name);
  }

  // safeOnionFile -----------------------------------------------------------------------------

  @Test
  @DisplayName("safeOnionFile_whenAbsolutePathProvided_expectIllegalArgument")
  void safeOnionFile_whenAbsolutePathProvided_expectIllegalArgument(@TempDir Path tmp) {
    // Arrange
    System.setProperty("user.home", tmp.toString());
    String absolute = tmp.resolve("abs.txt").toAbsolutePath().toString();

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> FileUtil.safeOnionFile(absolute));
  }

  @Test
  @DisplayName("safeOnionFile_whenElementCollapsesAfterSanitize_expectIllegalArgument")
  void safeOnionFile_whenElementCollapsesAfterSanitize_expectIllegalArgument(@TempDir Path tmp) {
    // Arrange
    System.setProperty("user.home", tmp.toString());
    String rel = "dir" + File.separator + "***";

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> FileUtil.safeOnionFile(rel));
  }

  @Test
  @DisplayName("safeOnionFile_whenRelativePath_expectFileCreatedUnderOnionDir")
  void safeOnionFile_whenRelativePath_expectFileCreatedUnderOnionDir(@TempDir Path tmp) {
    // Arrange
    System.setProperty("user.home", tmp.toString());
    String rel = "data" + File.separator + "file?.txt";
    File expected =
        tmp.resolve(".onion").resolve("data").resolve("file.txt").toAbsolutePath().toFile();

    // Act
    File created = FileUtil.safeOnionFile(rel);

    // Assert
    assertEquals(expected, created.getAbsoluteFile());
    assertTrue(created.exists(), "safeOnionFile should create the file");
  }

  // ensureExists ------------------------------------------------------------------------------

  @Test
  @DisplayName("ensureExists_whenParentsMissing_expectParentsAndFileCreated")
  void ensureExists_whenParentsMissing_expectParentsAndFileCreated(@TempDir Path tmp)
      throws IOException {
    // Arrange
    File target =
        tmp.resolve("nested").resolve("deep").resolve("file.bin").toAbsolutePath().toFile();

    // Act
    FileUtil.ensureExists(target);

    // Assert
    assertTrue(target.exists());
    assertTrue(target.getParentFile().exists());
  }

  // getOnionDir / getUserTempDir -------------------------------------------------------------

  @Test
  @DisplayName("getOnionDir_whenUserHomeNull_expectNull")
  void getOnionDir_whenUserHomeNull_expectNull() {
    // Arrange
    System.clearProperty("user.home");

    // Act
    File onionDir = FileUtil.getOnionDir();

    // Assert
    assertNull(onionDir);
  }

  @Test
  @DisplayName("getOnionDir_whenUserHomeSet_expectDirectoryCreated")
  void getOnionDir_whenUserHomeSet_expectDirectoryCreated(@TempDir Path tmp) {
    // Arrange
    System.setProperty("user.home", tmp.toString());

    // Act
    File onionDir = FileUtil.getOnionDir();

    // Assert
    assertNotNull(onionDir);
    assertTrue(onionDir.exists());
    assertEquals(tmp.resolve(".onion").toFile().getAbsolutePath(), onionDir.getAbsolutePath());
  }

  @Test
  @DisplayName("getUserTempDir_whenOnionDirPresent_expectTmpSubDirectoryCreated")
  void getUserTempDir_whenOnionDirPresent_expectTmpSubDirectoryCreated(@TempDir Path tmp) {
    // Arrange
    System.setProperty("user.home", tmp.toString());

    // Act
    File userTmp = FileUtil.getUserTempDir();

    // Assert
    assertNotNull(userTmp);
    assertEquals(tmp.resolve(".onion").resolve("tmp").toFile(), userTmp.getAbsoluteFile());
    assertTrue(userTmp.exists());
  }

  // createTempFile ---------------------------------------------------------------------------

  @Test
  @DisplayName("createTempFile_whenNullFile_usesUserTempDirAndOnionPrefix")
  void createTempFile_whenNullFile_usesUserTempDirAndOnionPrefix(@TempDir Path tmp)
      throws IOException {
    // Arrange
    System.setProperty("user.home", tmp.toString());
    File expectedParent = tmp.resolve(".onion").resolve("tmp").toFile();

    // Act
    File temp = FileUtil.createTempFile(null);

    // Assert
    assertTrue(temp.exists());
    assertEquals(expectedParent.getAbsoluteFile(), temp.getParentFile().getAbsoluteFile());
    assertTrue(temp.getName().startsWith("onion"));
  }

  @Test
  @DisplayName("createTempFile_whenShortNameProvided_expectNameExtendedToThreeChars")
  void createTempFile_whenShortNameProvided_expectNameExtendedToThreeChars(@TempDir Path tmp)
      throws IOException {
    // Arrange
    File requested = tmp.resolve("ab").toFile();

    // Act
    File temp = FileUtil.createTempFile(requested);

    // Assert
    assertTrue(temp.exists());
    assertEquals(tmp.toFile().getAbsoluteFile(), temp.getParentFile().getAbsoluteFile());
    assertTrue(temp.getName().startsWith("abonion"));
  }

  // skipFully --------------------------------------------------------------------------------

  @Test
  @DisplayName("skipFully_whenSkipReturnsZeroThenReadProgresses_expectSuccess")
  void skipFully_whenSkipReturnsZeroThenReadProgresses_expectSuccess() throws Exception {
    // Arrange
    try (InputStream stream = new SkipZeroThenReadStream(new byte[] {1, 2, 3})) {
      // Act + Assert
      assertDoesNotThrow(() -> FileUtil.skipFully(stream, 3));
    }
  }

  @Test
  @DisplayName("skipFully_whenEndOfStreamReached_expectEOFException")
  void skipFully_whenEndOfStreamReached_expectEOFException() throws Exception {
    // Arrange
    try (InputStream stream =
        new InputStream() {
          @Override
          public int read(byte @NotNull [] b, int off, int len) {
            return -1;
          }

          @Override
          public long skip(long n) {
            return 0;
          }

          @Override
          public int read() {
            return -1;
          }
        }) {

      // Act + Assert
      assertThrows(EOFException.class, () -> FileUtil.skipFully(stream, 1));
    }
  }

  // helpers ----------------------------------------------------------------------------------

  private static class SkipZeroThenReadStream extends InputStream {

    private final byte[] data;
    private int index = 0;
    private boolean skipCalled = false;

    private SkipZeroThenReadStream(byte[] data) {
      this.data = data;
    }

    @Override
    public long skip(long n) {
      if (!skipCalled) {
        skipCalled = true;
        return 0;
      }
      int remaining = data.length - index;
      int toSkip = (int) Math.min(n, remaining);
      index += toSkip;
      return toSkip;
    }

    @Override
    public int read(byte @NotNull [] b, int off, int len) {
      if (index >= data.length) {
        return -1;
      }
      int toCopy = Math.min(len, data.length - index);
      System.arraycopy(data, index, b, off, toCopy);
      index += toCopy;
      return toCopy;
    }

    @Override
    public int read() {
      if (index >= data.length) {
        return -1;
      }
      return data[index++] & 0xFF;
    }
  }
}
