package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Answers;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link FileUtil}.
 *
 * <p>Tests follow AAA style, avoid flakiness, and use deterministic inputs. Mockito is used to
 * control external I/O behavior where needed.
 */
@SuppressWarnings("java:S100")
class FileUtilTest {

  // ------------------------ sanitizeFileName() ---------------------------------

  @ParameterizedTest(name = "{0} → {2} on {1}")
  @MethodSource("sanitizeCases")
  @DisplayName("sanitizeFileName_whenVariousInputs_expectOSSpecificRulesApplied")
  void sanitizeFileName_whenVariousInputs_expectOSSpecificRulesApplied(
      String input, FileUtil.OperatingSystem os, String expected) {
    // Arrange + Act
    String actual = FileUtil.sanitizeFileName(input, os, "");

    // Assert
    assertEquals(expected, actual);
  }

  private static Stream<Arguments> sanitizeCases() {
    return Stream.of(
        // Windows reserved basename: prefix underscore
        Arguments.of("con.txt", FileUtil.OperatingSystem.WINDOWS, "_con.txt"),
        // Trailing dot/space removed on Windows
        Arguments.of("file. ", FileUtil.OperatingSystem.WINDOWS, "file"),
        // Slash is forbidden on Unix-like systems → replaced with space
        Arguments.of("a/b", FileUtil.OperatingSystem.LINUX, "a b"),
        Arguments.of("a/b", FileUtil.OperatingSystem.GENERIC_UNIX, "a b"),
        // Unknown = conservative rules (union); keep behavior consistent
        Arguments.of("a/b.", FileUtil.OperatingSystem.UNKNOWN, "a b"));
  }

  @Test
  @DisplayName("sanitizeFileName_whenEmpty_expectInvalidFilenamePlaceholder")
  void sanitizeFileName_whenEmpty_expectInvalidFilenamePlaceholder() {
    // Arrange
    String input = "";

    // Act
    String actual = FileUtil.sanitizeFileName(input, FileUtil.OperatingSystem.WINDOWS, "");

    // Assert
    assertEquals("Invalid filename", actual);
  }

  @Test
  @DisplayName("sanitizeFileName_whenExtraCharsExhaustDefaults_expectIllegalArgument")
  void sanitizeFileName_whenExtraCharsExhaustDefaults_expectIllegalArgument() {
    // Arrange: extra chars include space, underscore, and hyphen → no default replacement left
    String extra = " -_";

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> FileUtil.sanitizeFileName("name", FileUtil.OperatingSystem.WINDOWS, extra));
  }

  @Test
  @DisplayName("sanitize_whenMimeTypeProvided_expectForcedExtension")
  void sanitize_whenMimeTypeProvided_expectForcedExtension() {
    // Arrange
    String input = "doc.txt";

    // Act
    String actual = FileUtil.sanitize(input, "application/pdf");

    // Assert: DefaultMIMETypes.forceExtension() appends .pdf if old ext is invalid
    assertEquals("doc.txt.pdf", actual);
  }

  @Test
  @DisplayName("sanitize_whenMimeTypeNull_expectSimpleSanitize")
  void sanitize_whenMimeTypeNull_expectSimpleSanitize() {
    assertEquals("abc", FileUtil.sanitize("abc", null));
  }

  // ------------------------ skipFully() ----------------------------------------

  @Test
  @DisplayName("skipFully_whenZeroBytes_expectNoop")
  void skipFully_whenZeroBytes_expectNoop() throws Exception {
    // Arrange
    InputStream in = new ByteArrayInputStream(new byte[] {1, 2, 3});

    // Act + Assert: should not throw and stream remains at the start
    assertDoesNotThrow(() -> FileUtil.skipFully(in, 0));
    assertEquals(1, in.read());
  }

  @Test
  @DisplayName("skipFully_whenProgressesInChunks_expectSuccess")
  void skipFully_whenProgressesInChunks_expectSuccess() throws Exception {
    // Arrange: mock skip() to advance in multiple steps
    InputStream is = mock(InputStream.class);
    when(is.skip(anyLong())).thenReturn(3L, 5L, 2L);

    // Act + Assert: should not throw and perform 3 skip calls
    assertDoesNotThrow(() -> FileUtil.skipFully(is, 10));
    network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
        verify(is, times(3)).skip(anyLong()));
  }

  @Test
  @DisplayName("skipFully_whenSkipReturnsZero_expectIOException")
  void skipFully_whenSkipReturnsZero_expectIOException() throws Exception {
    // Arrange
    InputStream is = mock(InputStream.class);
    when(is.skip(anyLong())).thenReturn(0L);

    // Act + Assert
    assertThrows(IOException.class, () -> FileUtil.skipFully(is, 5));
    network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
        verify(is, atLeastOnce()).skip(anyLong()));
  }

  // ------------------------ readUTF() ------------------------------------------

  @Test
  @DisplayName("readUTF_whenFileAndStreamOffsets_expectDecodedSubstring")
  void readUTF_whenFileAndStreamOffsets_expectDecodedSubstring(@TempDir Path tmp) throws Exception {
    // Arrange
    Path f = tmp.resolve("utf.txt");
    String content = "abc\néé\nxyz"; // includes non-ASCII
    Files.writeString(f, content);

    // Act
    StringBuilder full = FileUtil.readUTF(f.toFile());
    StringBuilder from3 = FileUtil.readUTF(Files.newInputStream(f), 3);

    // Assert
    assertEquals(content, full.toString());
    assertEquals(content.substring(3), from3.toString());
  }

  @Test
  @DisplayName("readUTF_whenOffsetBeyondLength_expectIOException")
  void readUTF_whenOffsetBeyondLength_expectIOException(@TempDir Path tmp) throws Exception {
    // Arrange
    Path f = tmp.resolve("short.txt");
    Files.writeString(f, "abc");

    // Act + Assert
    try (InputStream in = Files.newInputStream(f)) {
      assertThrows(IOException.class, () -> FileUtil.readUTF(in, 10));
    }
  }

  // ------------------------ copy() ---------------------------------------------

  @Test
  @DisplayName("copy_whenLengthMinusOne_expectCopyUntilEOF")
  void copy_whenLengthMinusOne_expectCopyUntilEOF() throws Exception {
    // Arrange
    byte[] data = new byte[1024];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i & 0xFF);
    ByteArrayInputStream in = new ByteArrayInputStream(data);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    FileUtil.copy(in, out, -1);

    // Assert
    assertArrayEquals(data, out.toByteArray());
  }

  @Test
  @DisplayName("copy_whenExactLength_expectCopiedAndNoExtra")
  void copy_whenExactLength_expectCopiedAndNoExtra() throws Exception {
    // Arrange
    byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);
    ByteArrayInputStream in = new ByteArrayInputStream(data);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    FileUtil.copy(in, out, data.length);

    // Assert
    assertArrayEquals(data, out.toByteArray());
  }

  @Test
  @DisplayName("copy_whenLengthTooLarge_expectEOFException")
  void copy_whenLengthTooLarge_expectEOFException() {
    // Arrange
    byte[] data = {1, 2, 3};
    ByteArrayInputStream in = new ByteArrayInputStream(data);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(EOFException.class, () -> FileUtil.copy(in, out, 10));
  }

  // ------------------------ moveTo()/writeTo() ---------------------------------

  @Test
  @DisplayName("moveTo_whenAtomicMoveSupported_expectTrue")
  void moveTo_whenAtomicMoveSupported_expectTrue(@TempDir Path tmp) throws Exception {
    // Arrange
    Path src = tmp.resolve("from.bin");
    Path dst = tmp.resolve("to.bin");
    Files.write(src, List.of("x"));

    try (MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.ATOMIC_MOVE)))
          .then(_ -> dst);

      // Act
      boolean ok = FileUtil.moveTo(src.toFile(), dst.toFile());

      // Assert
      assertTrue(ok);
    }
  }

  @Test
  @DisplayName("moveTo_whenAtomicNotSupported_thenFallbackSucceeds_expectTrue")
  void moveTo_whenAtomicNotSupported_thenFallbackSucceeds_expectTrue(@TempDir Path tmp)
      throws Exception {
    // Arrange
    Path src = tmp.resolve("from2.bin");
    Path dst = tmp.resolve("to2.bin");
    Files.write(src, List.of("y"));

    try (MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.ATOMIC_MOVE)))
          .thenThrow(new java.nio.file.AtomicMoveNotSupportedException("a", "b", "nope"));
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.REPLACE_EXISTING)))
          .then(_ -> dst);

      // Act
      boolean ok = FileUtil.moveTo(src.toFile(), dst.toFile());

      // Assert
      assertTrue(ok);
    }
  }

  @Test
  @DisplayName("moveTo_whenIOExceptionOnAtomic_expectFallbackReplaceSucceeds")
  void moveTo_whenIOExceptionOnAtomic_expectFallbackReplaceSucceeds(@TempDir Path tmp)
      throws Exception {
    // Arrange
    Path src = tmp.resolve("from3.bin");
    Path dst = tmp.resolve("to3.bin");
    Files.write(src, List.of("z"));

    try (MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.ATOMIC_MOVE)))
          .thenThrow(new IOException("boom"));

      // Act
      boolean ok = FileUtil.moveTo(src.toFile(), dst.toFile());

      // Assert
      assertTrue(ok);
    }
  }

  @Test
  @DisplayName("moveTo_overwriteFalseAndDestExists_expectFalse")
  void moveTo_overwriteFalseAndDestExists_expectFalse(@TempDir Path tmp) throws Exception {
    // Arrange
    Path src = tmp.resolve("from4.bin");
    Path dst = tmp.resolve("to4.bin");
    Files.write(src, List.of("1"));
    Files.write(dst, List.of("2"));

    // Act
    boolean ok = FileUtil.moveTo(src.toFile(), dst.toFile(), false);

    // Assert
    assertFalse(ok);
  }

  @Test
  @DisplayName("writeTo_whenMoveSucceeds_expectFileCreatedWithContent")
  void writeTo_whenMoveSucceeds_expectFileCreatedWithContent(@TempDir Path tmp) throws Exception {
    // Arrange
    Path target = tmp.resolve("target.txt");
    byte[] data = "Hello".getBytes(StandardCharsets.UTF_8);

    // Act: use real filesystem move
    boolean ok = FileUtil.writeTo(new ByteArrayInputStream(data), target.toFile());

    // Assert
    assertTrue(ok);
    assertArrayEquals(data, Files.readAllBytes(target));
  }

  @Test
  @DisplayName("writeTo_whenMoveFails_expectFalseAndNoTarget")
  void writeTo_whenMoveFails_expectFalseAndNoTarget(@TempDir Path tmp) throws Exception {
    // Arrange
    Path target = tmp.resolve("target2.txt");
    byte[] data = "Hello2".getBytes(StandardCharsets.UTF_8);
    int initialFiles = countEntries(tmp);

    try (MockedStatic<FileUtil> fu = mockStatic(FileUtil.class, Answers.CALLS_REAL_METHODS)) {
      fu.when(() -> FileUtil.moveTo(any(File.class), eq(target.toFile()))).thenReturn(false);

      // Act
      boolean ok = FileUtil.writeTo(new ByteArrayInputStream(data), target.toFile());

      // Assert
      assertFalse(ok);
      assertFalse(Files.exists(target));
      assertEquals(initialFiles, countEntries(tmp), "Temp file should be cleaned up");
    }
  }

  // ------------------------ removeAll()/secureDeleteAll()/secureDelete ---------

  @Test
  @DisplayName("removeAll_whenDirectoryTree_expectRecursiveDeletion")
  void removeAll_whenDirectoryTree_expectRecursiveDeletion(@TempDir Path tmp) throws Exception {
    // Arrange
    Path dir = tmp.resolve("root");
    Path sub = dir.resolve("sub");
    Files.createDirectories(sub);
    Files.write(dir.resolve("a.bin"), new byte[] {1});
    Files.write(sub.resolve("b.bin"), new byte[] {2});

    // Act
    boolean ok = FileUtil.removeAll(dir.toFile());

    // Assert
    assertTrue(ok);
    assertFalse(Files.exists(dir));
  }

  @Test
  @DisplayName("secureDelete_whenNonexistent_expectNoThrow")
  void secureDelete_whenNonexistent_expectNoThrow(@TempDir Path tmp) {
    // Arrange
    Path f = tmp.resolve("missing.bin");

    // Act + Assert: should not throw, and the path remains absent
    assertDoesNotThrow(() -> FileUtil.secureDelete(f.toFile()));
    assertTrue(Files.notExists(f));
  }

  @Test
  @DisplayName("secureDelete_whenRegularFile_expectRemoved")
  void secureDelete_whenRegularFile_expectRemoved(@TempDir Path tmp) throws Exception {
    // Arrange
    Path f = tmp.resolve("present.bin");
    Files.write(f, new byte[] {1, 2, 3, 4});

    // Act
    FileUtil.secureDelete(f.toFile());

    // Assert
    assertFalse(Files.exists(f));
  }

  @Test
  @DisplayName("secureDeleteAll_whenFileDeleteThrows_expectFalse")
  void secureDeleteAll_whenFileDeleteThrows_expectFalse(@TempDir Path tmp) throws Exception {
    // Arrange: mock FileUtil.secureDelete to throw
    Path f = tmp.resolve("boom.bin");
    Files.write(f, new byte[] {1});

    try (MockedStatic<FileUtil> fu = mockStatic(FileUtil.class, Answers.CALLS_REAL_METHODS)) {
      fu.when(() -> FileUtil.secureDelete(eq(f.toFile())))
          .thenThrow(new IOException("cannot delete"));

      // Act
      boolean ok = FileUtil.secureDeleteAll(f.toFile());

      // Assert
      assertFalse(ok);
    }
  }

  // ------------------------ equals()/canonical/temp/copyFile -------------------

  @Test
  @DisplayName("equals_whenSamePathDifferentForms_expectTrue")
  void equals_whenSamePathDifferentForms_expectTrue(@TempDir Path tmp) throws Exception {
    // Arrange
    Path file = tmp.resolve("x.txt");
    Files.write(file, List.of("x"));
    File a = file.toFile();
    Path parent = file.getParent();
    assertNotNull(parent);
    File b = new File(parent.toFile(), "." + File.separator + file.getFileName());

    // Act + Assert
    assertTrue(FileUtil.equals(a, b));
  }

  @Test
  @DisplayName("equals_whenDifferentFiles_expectFalse")
  void equals_whenDifferentFiles_expectFalse(@TempDir Path tmp) throws Exception {
    // Arrange
    Path a = tmp.resolve("a.txt");
    Path b = tmp.resolve("b.txt");
    Files.write(a, List.of("a"));
    Files.write(b, List.of("b"));

    // Act + Assert
    assertFalse(FileUtil.equals(a.toFile(), b.toFile()));
  }

  @Test
  @DisplayName("getCanonicalFile_whenRelativeSegments_expectNormalizedAbsolute")
  void getCanonicalFile_whenRelativeSegments_expectNormalizedAbsolute(@TempDir Path tmp)
      throws Exception {
    // Arrange
    Path dir = Files.createDirectories(tmp.resolve("canon"));
    Path file = dir.resolve("f.txt");
    Files.write(file, List.of("x"));
    File withDots =
        new File(
            dir.toFile(),
            "." + File.separator + "sub" + File.separator + ".." + File.separator + "f.txt");

    // Act
    File canon = FileUtil.getCanonicalFile(withDots);

    // Assert
    assertEquals(file.toRealPath().toFile(), canon);
  }

  @Test
  @DisplayName("createTempFile_whenPrefixShort_expectDashTmpInserted")
  void createTempFile_whenPrefixShort_expectDashTmpInserted(@TempDir Path tmp) throws Exception {
    // Arrange
    String prefix = "ab";

    // Act
    File f = FileUtil.createTempFile(prefix, ".txt", tmp.toFile());

    // Assert
    assertTrue(f.getName().startsWith("ab-TMP"));
    assertTrue(f.exists());
  }

  @Test
  @DisplayName("copyFile_whenValidPaths_expectCopiedWithAttributes")
  void copyFile_whenValidPaths_expectCopiedWithAttributes(@TempDir Path tmp) throws Exception {
    // Arrange
    Path src = tmp.resolve("src.bin");
    Path dst = tmp.resolve("dst.bin");
    byte[] data = {7, 8, 9};
    Files.write(src, data);

    // Act
    boolean ok = FileUtil.copyFile(src.toFile(), dst.toFile());

    // Assert
    assertTrue(ok);
    assertArrayEquals(data, Files.readAllBytes(dst));
  }

  @Test
  @DisplayName("copyFile_whenCopyThrows_expectFalse")
  void copyFile_whenCopyThrows_expectFalse(@TempDir Path tmp) throws Exception {
    // Arrange
    Path src = tmp.resolve("src2.bin");
    Path dst = tmp.resolve("dst2.bin");
    Files.write(src, new byte[] {1});

    try (MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      files
          .when(
              () ->
                  Files.copy(
                      eq(src),
                      eq(dst),
                      eq(StandardCopyOption.REPLACE_EXISTING),
                      eq(StandardCopyOption.COPY_ATTRIBUTES)))
          .thenThrow(new IOException("boom"));

      // Act
      boolean ok = FileUtil.copyFile(src.toFile(), dst.toFile());

      // Assert
      assertFalse(ok);
    }
  }

  // ------------------------ equalStreams()/fill() ------------------------------

  @Test
  @DisplayName("equalStreams_whenEqualContent_expectTrue")
  void equalStreams_whenEqualContent_expectTrue() throws Exception {
    // Arrange
    byte[] data = new byte[2 * FileUtil.BUFFER_SIZE + 10];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i * 31);

    // Act
    boolean equal =
        FileUtil.equalStreams(
            new ByteArrayInputStream(data), new ByteArrayInputStream(data), data.length);

    // Assert
    assertTrue(equal);
  }

  @Test
  @DisplayName("equalStreams_whenDifferentByte_expectFalse")
  void equalStreams_whenDifferentByte_expectFalse() throws Exception {
    // Arrange
    byte[] a = {1, 2, 3, 4, 5};
    byte[] b = {1, 2, 9, 4, 5};

    // Act
    boolean equal =
        FileUtil.equalStreams(new ByteArrayInputStream(a), new ByteArrayInputStream(b), 5);

    // Assert
    assertFalse(equal);
  }

  @Test
  @DisplayName("equalStreams_whenShorterStream_expectEOFException")
  void equalStreams_whenShorterStream_expectEOFException() {
    // Arrange
    byte[] a = {1, 2, 3};
    byte[] b = {1, 2};

    // Act + Assert
    assertThrows(
        EOFException.class,
        () -> FileUtil.equalStreams(new ByteArrayInputStream(a), new ByteArrayInputStream(b), 3));
  }

  @Test
  @DisplayName("equalStreams_whenSizeZero_expectTrue")
  void equalStreams_whenSizeZero_expectTrue() throws Exception {
    assertTrue(
        FileUtil.equalStreams(
            new ByteArrayInputStream(new byte[0]), new ByteArrayInputStream(new byte[0]), 0));
  }

  // ------------------------ getLogTailReader() ---------------------------------

  @Test
  @DisplayName("getLogTailReader_whenTruncated_expectStartsAtNextFullLine")
  void getLogTailReader_whenTruncated_expectStartsAtNextFullLine(@TempDir Path tmp)
      throws Exception {
    // Arrange: ASCII-only content to make byte counts == char counts
    Path log = tmp.resolve("app.log");
    String content = "l1\nline2\nline3\n"; // 3 lines
    Files.writeString(log, content, StandardCharsets.UTF_8);
    long total = Files.size(log);

    // Choose a limit that lands in the middle of "line2" so the partial line is discarded
    long byteLimit = 8; // ensures skip > 0 on typical sizes here
    assertTrue(total > byteLimit);

    // Act
    try (LineReadingInputStream in = FileUtil.getLogTailReader(log.toFile(), byteLimit)) {
      String first = in.readLine(1000, 128, true);
      // Assert: should start at the first full line after the truncated boundary
      assertEquals("line3", first);
    }
  }

  // --- helpers -----------------------------------------------------------------

  private static int countEntries(Path dir) throws IOException {
    try (java.util.stream.Stream<Path> s = Files.list(dir)) {
      return (int) s.count();
    }
  }
}
