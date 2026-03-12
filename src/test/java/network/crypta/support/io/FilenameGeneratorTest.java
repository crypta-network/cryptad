package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;

/**
 * Unit tests for {@link FilenameGenerator}.
 *
 * <p>Tests follow AAA style and use deterministic Randoms. External IO is kept within
 * {@code @TempDir} folders; Random is mocked where appropriate.
 */
class FilenameGeneratorTest {

  @TempDir Path tempDir;

  private AutoCloseable mocks;

  private static final String PREFIX = "fgtest-";

  @BeforeEach
  void setUp() {
    mocks = MockitoAnnotations.openMocks(this);
  }

  @AfterEach
  void tearDown() throws Exception {
    if (mocks != null) mocks.close();
  }

  // --- Constructor behavior ---

  @Test
  void constructor_whenDirIsFile_throwsIOException() throws IOException {
    // Arrange
    Path filePath = Files.createFile(tempDir.resolve("not-a-dir"));
    Random rnd = new Random(1);

    // Act + Assert
    assertThrows(
        IOException.class, () -> new FilenameGenerator(rnd, false, filePath.toFile(), PREFIX));
  }

  @Test
  void constructor_whenDirIsNull_usesSystemTmpDir() throws IOException {
    // Arrange
    Random rnd = new Random(2);
    File expected = FileUtil.getCanonicalFile(new File(System.getProperty("java.io.tmpdir")));

    // Act
    FilenameGenerator fg = new FilenameGenerator(rnd, false, null, PREFIX);

    // Assert
    assertEquals(expected, fg.getDir());
  }

  @Test
  void constructor_whenWipeFilesTrue_deletesOnlyFilesWithPrefix() throws IOException {
    // Arrange: create files in temp dir, some with the prefix, some without
    Path prefA = Files.createFile(tempDir.resolve(PREFIX + "A"));
    Path prefB = Files.createFile(tempDir.resolve(PREFIX + "B"));
    Path other = Files.createFile(tempDir.resolve("other.txt"));
    // On non-Windows systems the match is case-sensitive
    Path caseVariant = Files.createFile(tempDir.resolve(PREFIX.toUpperCase(Locale.ROOT) + "C"));

    // Act
    new FilenameGenerator(new Random(3), true, tempDir.toFile(), PREFIX);

    // Assert
    assertFalse(Files.exists(prefA), "prefix file A should be deleted");
    assertFalse(Files.exists(prefB), "prefix file B should be deleted");
    assertTrue(Files.exists(other), "non-prefix file should remain");
    // On non-Windows, different case should not be deleted
    if (File.separatorChar != '\\') {
      assertTrue(Files.exists(caseVariant), "case-variant should remain on non-Windows");
    }
  }

  // --- makeRandomFilename / makeRandomFile ---

  @Test
  void makeRandomFilename_whenMinusOneThenCollisionThenSuccess_returnsNewIdAndCreatesFile()
      throws IOException {
    // Arrange
    Random rnd = mock(Random.class);
    // Sequence: -1 (skip), collision (hex of 66 -> "42"), then success (67 -> "43")
    when(rnd.nextLong()).thenReturn(-1L, 66L, 67L);

    FilenameGenerator fg = new FilenameGenerator(rnd, false, tempDir.toFile(), PREFIX);
    // Pre-create the colliding file for id=66 ("42" in hex)
    Path colliding = tempDir.resolve(PREFIX + Long.toHexString(66L));
    Files.createFile(colliding);

    // Act
    long id = fg.makeRandomFilename();

    // Assert
    assertEquals(67L, id, "should return the first non-colliding id");
    File created = fg.getFilename(id);
    assertTrue(created.exists(), "created file must exist");
    assertThat(created.getName(), endsWith(Long.toHexString(67L)));
  }

  @Test
  void makeRandomFile_whenCalled_createsAndReturnsFile() throws IOException {
    // Arrange
    FilenameGenerator fg = new FilenameGenerator(new Random(4), false, tempDir.toFile(), PREFIX);

    // Act
    File file = fg.makeRandomFile();

    // Assert
    assertTrue(file.exists(), "random file should exist");
    String name = file.getName();
    assertTrue(name.startsWith(PREFIX), "name should start with prefix");
    assertTrue(name.length() > PREFIX.length(), "name should include hex id after prefix");
  }

  // --- getFilename ---

  @ParameterizedTest
  @MethodSource("idsForGetFilename")
  void getFilename_whenGivenId_returnsFileWithPrefixAndHex(long id, String expectedHex)
      throws IOException {
    // Arrange
    FilenameGenerator fg = new FilenameGenerator(new Random(5), false, tempDir.toFile(), PREFIX);

    // Act
    File f = fg.getFilename(id);

    // Assert
    assertTrue(
        FileUtil.equals(tempDir.toFile(), f.getParentFile()),
        "Parent dir should equal tempDir (canonicalized)");
    assertEquals(PREFIX + expectedHex, f.getName());
  }

  private static Stream<Arguments> idsForGetFilename() {
    return Stream.of(
        Arguments.of(0L, "0"),
        Arguments.of(1L, "1"),
        Arguments.of(16L, "10"),
        Arguments.of(-2L, Long.toHexString(-2L)));
  }

  // --- maybeMove semantics ---

  @Test
  void maybeMove_whenFileAlreadyMatches_returnsSameFile() throws IOException {
    // Arrange
    FilenameGenerator fg = new FilenameGenerator(new Random(6), false, tempDir.toFile(), PREFIX);
    long id = 0xabcL;
    File already = fg.getFilename(id);
    assertTrue(already.createNewFile());

    // Act
    File result = fg.maybeMove(already, 123L);

    // Assert
    assertSame(already, result);
    assertTrue(result.exists());
  }

  @Test
  void maybeMove_whenDestinationExists_returnsOriginalFile() throws IOException {
    // Arrange
    FilenameGenerator fg = new FilenameGenerator(new Random(7), false, tempDir.toFile(), PREFIX);

    long id = 0xCAFEBABEL;
    File dest = fg.getFilename(id);
    assertTrue(dest.createNewFile()); // destination occupied

    Path otherDir = Files.createDirectory(tempDir.resolve("other"));
    File src = otherDir.resolve("some.tmp").toFile();
    assertTrue(src.createNewFile());

    // Act
    File result = fg.maybeMove(src, id);

    // Assert
    assertSame(src, result, "should return original when move fails");
    assertTrue(src.exists(), "source should remain when move fails");
    assertTrue(dest.exists(), "dest should remain untouched");
  }

  @Test
  @DisplayName("maybeMove moves file into tmpDir when not matching and destination free")
  void maybeMove_whenNotMatchesAndDestinationFree_movesAndReturnsNewFile() throws IOException {
    // Arrange
    FilenameGenerator fg = new FilenameGenerator(new Random(8), false, tempDir.toFile(), PREFIX);
    long id = 0x1234L;
    File expected = fg.getFilename(id);
    assertFalse(expected.exists());

    Path otherDir = Files.createDirectory(tempDir.resolve("outside"));
    File src = otherDir.resolve("to-move.tmp").toFile();
    assertTrue(src.createNewFile());

    // Act
    File moved = fg.maybeMove(src, id);

    // Assert
    assertEquals(expected, moved, "should return file in generator dir");
    assertTrue(moved.exists(), "moved file should exist at destination");
    assertFalse(src.exists(), "source file should be gone");
  }
}
