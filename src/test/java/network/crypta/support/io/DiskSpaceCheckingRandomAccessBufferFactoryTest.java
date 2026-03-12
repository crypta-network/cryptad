package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DiskSpaceCheckingRandomAccessBufferFactoryTest {

  @TempDir Path tmp;

  @Test
  void makeRAF_whenEnoughSpace_returnsUnderlyingResult() throws IOException {
    // Arrange
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    File dir = mock(File.class);
    long min = 100L;
    long size = 50L;
    when(dir.getUsableSpace()).thenReturn(1_000L);
    LockableRandomAccessBuffer expected = mock(LockableRandomAccessBuffer.class);
    when(underlying.makeRAF(size)).thenReturn(expected);
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, min);

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(size)) {
      // Assert
      assertSame(expected, raf);
      try (var _ = verify(underlying).makeRAF(size)) {
        assertTrue(true);
      }
      verifyNoMoreInteractions(underlying);
    }
  }

  @Test
  void makeRAF_whenInsufficientSpace_throwsInsufficientDiskSpaceException() {
    // Arrange
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    File dir = mock(File.class);
    long min = 100L;
    long size = 50L;
    when(dir.getUsableSpace()).thenReturn(min + size); // equality is not enough (strict >)
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, min);

    // Act + Assert
    assertThrows(
        InsufficientDiskSpaceException.class,
        () -> {
          try (var _ = factory.makeRAF(size)) {
            assertTrue(true);
          }
        });
    verifyNoInteractions(underlying);
  }

  @Test
  void makeRAFWithInitialContents_whenEnoughSpace_callsUnderlying() throws IOException {
    // Arrange
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    File dir = mock(File.class);
    when(dir.getUsableSpace()).thenReturn(10_000L);
    byte[] data = new byte[] {0, 1, 2, 3, 4, 5};
    int offset = 2;
    int size = 3;
    boolean readOnly = false;
    LockableRandomAccessBuffer expected = mock(LockableRandomAccessBuffer.class);
    when(underlying.makeRAF(data, offset, size, readOnly)).thenReturn(expected);
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, 100L);

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(data, offset, size, readOnly)) {
      // Assert
      assertSame(expected, raf);
      try (var _ = verify(underlying).makeRAF(data, offset, size, readOnly)) {
        assertTrue(true);
      }
      verifyNoMoreInteractions(underlying);
    }
  }

  @Test
  void makeRAFWithInitialContents_whenInsufficientSpace_throwsInsufficientDiskSpaceException() {
    // Arrange
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    File dir = mock(File.class);
    int size = 5;
    long min = 100L;
    when(dir.getUsableSpace()).thenReturn(min + size); // not strictly greater
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, min);

    // Act + Assert
    assertThrows(
        InsufficientDiskSpaceException.class,
        () -> {
          try (LockableRandomAccessBuffer ignored = factory.makeRAF(new byte[10], 0, size, false)) {
            assertNotNull(ignored);
          }
        });
    verifyNoInteractions(underlying);
  }

  @Test
  void makeRAFWithInitialContents_whenNullInitialContents_callsUnderlying() throws IOException {
    // Arrange
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    File dir = mock(File.class);
    when(dir.getUsableSpace()).thenReturn(10_000L);
    LockableRandomAccessBuffer expected = mock(LockableRandomAccessBuffer.class);
    when(underlying.makeRAF(null, 0, 0, true)).thenReturn(expected);
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, 0L);

    // Act
    try (LockableRandomAccessBuffer raf = factory.makeRAF(null, 0, 0, true)) {
      // Assert
      assertSame(expected, raf);
      try (var _ = verify(underlying).makeRAF(null, 0, 0, true)) {
        assertTrue(true);
      }
    }
  }

  @Test
  void setMinDiskSpace_whenNegative_throwsIllegalArgumentException() {
    // Arrange
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    File dir = mock(File.class);
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, 0L);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> factory.setMinDiskSpace(-1L));
  }

  @Test
  void setMinDiskSpace_whenReduced_allowsSubsequentMakeRAF() throws IOException {
    // Arrange
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    File dir = mock(File.class);
    when(dir.getUsableSpace()).thenReturn(600L);
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, 1_000L);
    long size = 550L;

    // Act + Assert (first call should fail)
    assertThrows(
        InsufficientDiskSpaceException.class,
        () -> {
          try (LockableRandomAccessBuffer ignored = factory.makeRAF(size)) {
            assertNotNull(ignored);
          }
        });

    // Reduce min and retry
    LockableRandomAccessBuffer expected = mock(LockableRandomAccessBuffer.class);
    when(underlying.makeRAF(size)).thenReturn(expected);
    factory.setMinDiskSpace(0L);
    try (LockableRandomAccessBuffer raf = factory.makeRAF(size)) {
      assertSame(expected, raf);
    }
  }

  @Test
  void toString_whenCalled_containsUnderlyingToString() {
    // Arrange
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    when(underlying.toString()).thenReturn("UNDER");
    File dir = mock(File.class);
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, 0L);

    // Act
    String s = factory.toString();

    // Assert
    assertTrue(s.endsWith(":UNDER"), "toString should suffix underlying toString");
  }

  @Test
  void createNewRAF_whenFileDoesNotExist_throwsIOException() {
    // Arrange
    File dir = mock(File.class);
    when(dir.getUsableSpace()).thenReturn(10_000L);
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, 0L);
    File missing = tmp.resolve("missing.bin").toFile();
    long size = 123L;

    // Act + Assert
    IOException ex =
        assertThrows(
            IOException.class,
            () -> {
              try (PooledFileRandomAccessBuffer ignored =
                  factory.createNewRAF(missing, size, new Random(1))) {
                assertNotNull(ignored);
              }
            });
    assertTrue(ex.getMessage().contains("does not exist"));
    assertFalse(missing.exists());
  }

  @Test
  void createNewRAF_whenFileHasNonZeroLength_throwsIOExceptionAndDeletesFile() throws IOException {
    // Arrange
    File dir = mock(File.class);
    when(dir.getUsableSpace()).thenReturn(10_000L);
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, 0L);
    Path p = tmp.resolve("nonzero.dat");
    Files.write(p, new byte[] {42}); // create with one byte
    File f = p.toFile();

    // Act + Assert
    IOException ex =
        assertThrows(
            IOException.class,
            () -> {
              try (PooledFileRandomAccessBuffer ignored =
                  factory.createNewRAF(f, 10L, new Random(7))) {
                assertNotNull(ignored);
              }
            });
    assertTrue(ex.getMessage().contains("wrong length"));
    assertFalse(f.exists(), "File should be deleted on failure");
  }

  @Test
  void createNewRAF_whenInsufficientSpace_throwsAndDeletesFile() throws IOException {
    // Arrange
    File dir = mock(File.class);
    long min = 500L;
    long size = 500L;
    when(dir.getUsableSpace()).thenReturn(min + size); // equality not sufficient
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, min);
    Path p = tmp.resolve("insufficient.dat");
    Files.createFile(p); // zero length
    File f = p.toFile();

    // Act + Assert
    assertThrows(
        InsufficientDiskSpaceException.class,
        () -> {
          try (PooledFileRandomAccessBuffer ignored =
              factory.createNewRAF(f, size, new Random(1234))) {
            assertNotNull(ignored);
          }
        });
    assertFalse(f.exists(), "File should be deleted when creation fails");
  }

  @Test
  void createNewRAF_whenEnoughSpace_constructsPooledFileRandomAccessBufferAndKeepsFile()
      throws IOException {
    // Arrange
    File dir = mock(File.class);
    long min = 10L;
    long size = 123L;
    when(dir.getUsableSpace()).thenReturn(min + size + 1); // strictly greater
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, min);
    Path p = tmp.resolve("ok.dat");
    Files.createFile(p); // zero length file
    File f = p.toFile();
    Random rnd = new Random(42L);

    // Act
    try (PooledFileRandomAccessBuffer raf = factory.createNewRAF(f, size, rnd)) {
      // Assert
      assertNotNull(raf);
      assertTrue(f.exists(), "File should remain after successful creation");
      assertEquals(size, f.length(), "File should be preallocated to requested size");
    }
  }

  @Test
  void checkDiskSpace_whenFileNotChild_returnsTrue() throws IOException {
    // Arrange: real directories so FileUtil.isParent() returns false
    Path dirPath = tmp.resolve("parent");
    Files.createDirectories(dirPath);
    Path otherDir = tmp.resolve("other");
    Files.createDirectories(otherDir);

    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);
    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dirPath.toFile(), /*min*/ 100L);
    File notChild = otherDir.resolve("file.bin").toFile();

    // Act
    boolean ok = factory.checkDiskSpace(notChild, 10, 20);

    // Assert
    assertTrue(ok, "Should not block when file is outside monitored dir");
  }

  @ParameterizedTest
  @ValueSource(longs = {0L, Long.MAX_VALUE})
  void checkDiskSpace_whenFileChild_respectsThreshold(long min) throws IOException {
    // Arrange: real parent/child to exercise FileUtil.isParent(); choose inputs with deterministic
    // outcomes regardless of available space.
    Path dirPath = tmp.resolve("child-parent");
    Files.createDirectories(dirPath);
    File dir = dirPath.toFile();
    File child = dirPath.resolve("child.bin").toFile();
    LockableRandomAccessBufferFactory underlying = mock(LockableRandomAccessBufferFactory.class);

    // toWrite=0, buffer=0 so condition reduces to (usableSpace >= min)
    int toWrite = 0;
    int buffer = 0;

    DiskSpaceCheckingRandomAccessBufferFactory factory =
        new DiskSpaceCheckingRandomAccessBufferFactory(underlying, dir, min);

    // Act
    boolean ok = factory.checkDiskSpace(child, toWrite, buffer);

    // Assert
    boolean expected = (min == 0L); // true for 0, false for Long.MAX_VALUE
    assertEquals(expected, ok);
  }
}
