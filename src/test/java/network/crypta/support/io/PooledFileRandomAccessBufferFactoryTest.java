package network.crypta.support.io;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.support.api.LockableRandomAccessBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Tests for {@link PooledFileRandomAccessBufferFactory}.
 *
 * <p>Strategy: mock {@link FilenameGenerator} to control the chosen identifier and file path while
 * using the real {@link PooledFileRandomAccessBuffer} implementation to exercise file creation,
 * preallocation, and error handling. Real filesystem is used under a JUnit-provided temporary
 * directory for determinism and isolation. All buffers are freed to avoid descriptor leaks.
 */
@SuppressWarnings("java:S100") // allow method_whenCondition_expectOutcome naming
class PooledFileRandomAccessBufferFactoryTest {

  @TempDir Path tmpDir;

  private static File fileForId(Path dir, long id) {
    return dir.resolve("prefix-" + Long.toHexString(id)).toFile();
  }

  private static FilenameGenerator mockFGFor(Path dir, long id, boolean createAsFile)
      throws IOException {
    File f = fileForId(dir, id);
    if (createAsFile) {
      Files.createFile(f.toPath());
    } else {
      Files.createDirectory(f.toPath());
    }
    FilenameGenerator fg = mock(FilenameGenerator.class);
    when(fg.makeRandomFilename()).thenReturn(id);
    when(fg.getFilename(id)).thenReturn(f);
    return fg;
  }

  // ---------------------------- makeRAF(long) ----------------------------

  @Test
  @DisplayName("makeRAF(long)_whenSizeZero_expectFileCreatedAndBufferReturned")
  void makeRAF_whenSizeZero_expectFileCreatedAndBufferReturned() throws IOException {
    // Arrange
    long id = 0xdeadbeefL;
    FilenameGenerator fg = mockFGFor(tmpDir, id, true);
    PooledFileRandomAccessBufferFactory factory = new PooledFileRandomAccessBufferFactory(fg);
    File f = fileForId(tmpDir, id);

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(0L)) {
      // Assert
      assertNotNull(raf);
      assertEquals(0L, raf.size());
      assertTrue(f.exists(), "backing file exists before free()");
      verify(fg, times(1)).makeRandomFilename();
      verify(fg, times(1)).getFilename(id);
      // Clean up
      raf.free();
    }
    assertFalse(f.exists(), "backing file removed on free()");
  }

  @Test
  @DisplayName("makeRAF(long)_whenPositiveSize_expectPreallocatedSize")
  void makeRAF_whenPositiveSize_expectPreallocatedSize() throws IOException {
    // Arrange
    long id = 0xabc123L;
    FilenameGenerator fg = mockFGFor(tmpDir, id, true);
    PooledFileRandomAccessBufferFactory factory = new PooledFileRandomAccessBufferFactory(fg);
    File f = fileForId(tmpDir, id);
    long req = 4096L;

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(req)) {
      // Assert
      assertEquals(req, raf.size());
      assertTrue(f.exists());
      assertEquals(req, f.length(), "file length should match preallocated size");
      // Clean up
      raf.free();
    }
    assertFalse(f.exists());
  }

  @Test
  @DisplayName("makeRAF(long)_whenConstructorThrows_expectTempDeleted")
  void makeRAF_whenConstructorThrows_expectTempDeleted() throws IOException {
    // Arrange: create a DIRECTORY at the path so RandomAccessFile(open) fails
    long id = 0x1111L;
    FilenameGenerator fg = mockFGFor(tmpDir, id, false);
    PooledFileRandomAccessBufferFactory factory = new PooledFileRandomAccessBufferFactory(fg);
    File f = fileForId(tmpDir, id);
    assertTrue(f.isDirectory());

    // Act + Assert (wrap in try-with-resources to satisfy resource analysis)
    assertThrows(
        IOException.class,
        () -> {
          try (var _ = factory.makeRAF(1L)) {
            fail("expected IOException");
          }
        });
    // Factory should best-effort delete the path even when it's a directory.
    assertFalse(f.exists(), "temporary path cleaned up on failure");
  }

  @Test
  @DisplayName("makeRAF(long)_whenNegativeSize_expectZeroLengthBuffer")
  void makeRAF_whenNegativeSize_expectZeroLengthBuffer() throws IOException {
    // Arrange: negative size is accepted by current implementation; results in 0-length buffer
    long id = 0x7777L;
    FilenameGenerator fg = mockFGFor(tmpDir, id, true);
    PooledFileRandomAccessBufferFactory factory = new PooledFileRandomAccessBufferFactory(fg);
    File f = fileForId(tmpDir, id);

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(-1L)) {
      // Assert
      assertEquals(0L, raf.size());
      assertEquals(0L, f.length());
      raf.free();
    }
    assertFalse(f.exists());
  }

  // ---------------------------- makeRAF(bytes, ..) ----------------------------

  @ParameterizedTest(name = "readOnly={0}")
  @ValueSource(booleans = {false, true})
  @DisplayName("makeRAF(bytes)_whenGivenData_expectContentAndReadOnlyRespected")
  void makeRAF_withInitialContents_whenGivenData_expectContentAndReadOnlyRespected(boolean readOnly)
      throws IOException {
    // Arrange
    long id = 0xfeedL;
    FilenameGenerator fg = mockFGFor(tmpDir, id, true);
    PooledFileRandomAccessBufferFactory factory = new PooledFileRandomAccessBufferFactory(fg);
    File f = fileForId(tmpDir, id);
    byte[] data = new byte[] {9, 8, 7, 6, 5};

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(data, 1, 3, readOnly)) {
      // Assert: size and initial content
      assertEquals(3L, raf.size());
      byte[] out = new byte[3];
      raf.pread(0, out, 0, 3);
      assertArrayEquals(new byte[] {8, 7, 6}, out);

      if (readOnly) {
        assertThrows(IOException.class, () -> raf.pwrite(0, new byte[] {1, 2, 3}, 0, 3));
      } else {
        raf.pwrite(0, new byte[] {1, 2, 3}, 0, 3);
        byte[] verify = new byte[3];
        raf.pread(0, verify, 0, 3);
        assertArrayEquals(new byte[] {1, 2, 3}, verify);
      }

      assertTrue(f.exists());
      assertThat(raf, instanceOf(PooledFileRandomAccessBuffer.class));
      raf.free();
    }
    assertFalse(f.exists());
  }

  @Test
  @DisplayName("makeRAF(bytes)_whenNullInitialContents_expectNullPointerAndTempDeleted")
  void makeRAF_withInitialContents_whenNull_expectNullPointerAndTempDeleted() throws IOException {
    // Arrange
    long id = 0x2222L;
    FilenameGenerator fg = mockFGFor(tmpDir, id, true);
    PooledFileRandomAccessBufferFactory factory = new PooledFileRandomAccessBufferFactory(fg);
    File f = fileForId(tmpDir, id);

    // Act + Assert: underlying RAF.write(null, ..) will throw NPE; factory deletes temp
    assertThrows(
        NullPointerException.class,
        () -> {
          try (var _ = factory.makeRAF(null, 0, 1, false)) {
            fail("expected NPE");
          }
        });
    assertFalse(f.exists());
  }

  @Test
  @DisplayName("makeRAF(bytes)_whenOffsetSizeOutOfBounds_expectIndexOutOfBoundsAndTempDeleted")
  void makeRAF_withInitialContents_whenOffsetSizeOutOfBounds_expectIndexOutOfBoundsAndTempDeleted()
      throws IOException {
    // Arrange
    long id = 0x3333L;
    FilenameGenerator fg = mockFGFor(tmpDir, id, true);
    PooledFileRandomAccessBufferFactory factory = new PooledFileRandomAccessBufferFactory(fg);
    File f = fileForId(tmpDir, id);
    byte[] data = new byte[] {1, 2, 3};

    // Act + Assert: RandomAccessFile.write(..) validates bounds and throws
    // IndexOutOfBoundsException
    assertThrows(
        IndexOutOfBoundsException.class,
        () -> {
          try (var _ = factory.makeRAF(data, 2, 2, false)) {
            fail("expected IndexOutOfBoundsException");
          }
        });
    assertFalse(f.exists());
  }
}
