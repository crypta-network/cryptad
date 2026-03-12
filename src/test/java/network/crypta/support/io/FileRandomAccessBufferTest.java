package network.crypta.support.io;

import java.io.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import network.crypta.support.api.LockableRandomAccessBuffer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;

/**
 * Tests for {@link FileRandomAccessBuffer} covering normal, boundary, and error paths.
 *
 * <p>AAA style is used throughout (Arrange, Act, Assert). We combine real temp files for end-to-end
 * behavior and Mockito for injected {@link RandomAccessFile} interactions and error simulation.
 */
class FileRandomAccessBufferTest {

  @TempDir Path tmpDir;

  private File newTempFile(String name) throws IOException {
    Path p = tmpDir.resolve(name);
    Files.deleteIfExists(p); // ensure clean
    Files.createFile(p);
    return p.toFile();
  }

  @Test
  void size_whenConstructedWithExplicitLength_returnsSame() throws Exception {
    // Arrange
    File f = newTempFile("explicit-length.bin");
    long length = 32;

    // Act + Assert
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, length, false)) {
      assertEquals(length, buf.size());
      buf.free();
    }
  }

  @Test
  void pread_whenWithinBounds_readsExpectedBytes() throws Exception {
    // Arrange
    File f = newTempFile("pread-ok.bin");
    long length = 16;
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, length, false)) {
      byte[] src = new byte[] {10, 20, 30, 40, 50, 60, 70, 80};
      buf.pwrite(4, src, 0, src.length);
      byte[] out = new byte[src.length];

      // Act
      buf.pread(4, out, 0, out.length);

      // Assert
      assertArrayEquals(src, out);
      buf.free();
    }
  }

  @Test
  void pwrite_whenWithinBounds_writesBytesCorrectly() throws Exception {
    // Arrange
    File f = newTempFile("pwrite-ok.bin");
    long length = 32;
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, length, false)) {
      byte[] data = new byte[8];
      new Random(1234).nextBytes(data);
      // Act
      buf.pwrite(8, data, 0, data.length);
      // Assert
      byte[] verify = new byte[data.length];
      buf.pread(8, verify, 0, verify.length);
      assertArrayEquals(data, verify);
      buf.free();
    }
  }

  @Test
  void pwrite_whenReadOnly_expectIOException() throws Exception {
    // Arrange
    File f = newTempFile("readonly.bin");
    // Pre-size the file, then open in read-only mode
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(8);
    }
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, true)) {
      byte[] data = {1, 2, 3};
      // Act + Assert
      IOException ex = assertThrows(IOException.class, () -> buf.pwrite(0, data, 0, data.length));
      assertThat(ex.getMessage(), containsString("Read only"));
      buf.free();
    }
  }

  static Arguments[] preadInvalidParams() {
    return new Arguments[] {
      Arguments.of(-1L, 1, IllegalArgumentException.class), // negative offset
      Arguments.of(10L, 1, IOException.class) // runs past end when size=10
    };
  }

  @ParameterizedTest(name = "pread offset={0} len={1} -> {2}")
  @MethodSource("preadInvalidParams")
  void pread_whenInvalidParams_expectException(long offset, int len, Class<? extends Exception> ex)
      throws Exception {
    // Arrange
    File f = newTempFile("pread-invalid.bin");
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, 10, false)) {
      byte[] out = new byte[Math.max(len, 1)];
      // Act + Assert
      assertThrows(ex, () -> buf.pread(offset, out, 0, len));
      buf.free();
    }
  }

  static Arguments[] pwriteInvalidParams() {
    return new Arguments[] {
      Arguments.of(-1L, 1, IllegalArgumentException.class), // negative offset
      Arguments.of(9L, 2, IOException.class) // runs past end when size=10
    };
  }

  @ParameterizedTest(name = "pwrite offset={0} len={1} -> {2}")
  @MethodSource("pwriteInvalidParams")
  void pwrite_whenInvalidParams_expectException(long offset, int len, Class<? extends Exception> ex)
      throws Exception {
    // Arrange
    File f = newTempFile("pwrite-invalid.bin");
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, 10, false)) {
      byte[] src = new byte[Math.max(len, 1)];
      // Act + Assert
      assertThrows(ex, () -> buf.pwrite(offset, src, 0, len));
      buf.free();
    }
  }

  @Test
  void pread_whenBufferNull_expectNullPointerException() throws Exception {
    // Arrange
    File f = newTempFile("pread-npe.bin");
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, 4, false)) {
      // Act + Assert (RAF.readFully will throw NPE)
      assertThrows(NullPointerException.class, () -> buf.pread(0, null, 0, 1));
      buf.free();
    }
  }

  @Test
  void pwrite_whenBufferNull_expectNullPointerException() throws Exception {
    // Arrange
    File f = newTempFile("pwrite-npe.bin");
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, 4, false)) {
      // Act + Assert (RAF.write will throw NPE)
      assertThrows(NullPointerException.class, () -> buf.pwrite(0, null, 0, 1));
      buf.free();
    }
  }

  @Test
  void pread_whenAfterClose_expectIOException() throws Exception {
    // Arrange
    File f = newTempFile("pread-closed.bin");
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, 8, false)) {
      buf.close();
      byte[] out = new byte[1];
      // Act + Assert
      assertThrows(IOException.class, () -> buf.pread(0, out, 0, 1));
      buf.free();
    }
  }

  @Test
  void pwrite_whenAfterClose_expectIOException() throws Exception {
    // Arrange
    File f = newTempFile("pwrite-closed.bin");
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, 8, false)) {
      buf.close();
      byte[] data = {1};
      // Act + Assert
      assertThrows(IOException.class, () -> buf.pwrite(0, data, 0, 1));
      buf.free();
    }
  }

  @Test
  void close_whenCalledTwice_underlyingClosedOnce() throws Exception {
    // Arrange
    RandomAccessFile raf = mock(RandomAccessFile.class);
    when(raf.length()).thenReturn(100L);
    File f = newTempFile("mock-close.bin");
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(raf, f, false)) {
      // Act
      buf.close();
      buf.close();
      // Assert
      verify(raf, times(1)).close();
      buf.free();
    }
  }

  @Test
  void lockOpen_whenUnlockTwice_secondCallThrows() throws Exception {
    // Arrange
    File f = newTempFile("lock-open.bin");
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, 1, false)) {
      var lock = buf.lockOpen();
      // Act + Assert
      assertDoesNotThrow(lock::unlock);
      assertThrows(IllegalStateException.class, lock::unlock);
      buf.free();
    }
  }

  @Test
  void free_whenSecureDeleteFalse_deletesFile() throws Exception {
    // Arrange
    File f = newTempFile("free-delete.bin");
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, 1, false)) {
      assertTrue(f.exists());
      // Act
      buf.free();
      // Assert
      assertFalse(f.exists(), "File should be removed");
    }
  }

  @Test
  void free_whenSecureDeleteTrue_deletesFile() throws Exception {
    // Arrange
    File f = newTempFile("free-secure-delete.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(1); // keep it tiny
    }
    try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, false)) {
      buf.setSecureDelete(true);
      assertTrue(f.exists());
      // Act
      buf.free();
      // Assert
      assertFalse(f.exists(), "File should be securely removed");
    }
  }

  @Nested
  class ResumeTests {
    @Test
    void onResume_whenFileMissing_expectResumeFailedException() throws Exception {
      // Arrange
      File f = newTempFile("resume-missing.bin");
      try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, 4, false)) {
        buf.close();
        assertTrue(f.delete());
        // Act + Assert
        assertThrows(ResumeFailedException.class, () -> buf.onResume(null));
      }
    }

    @Test
    void onResume_whenLengthMismatch_expectResumeFailedException() throws Exception {
      // Arrange: create file length=20, then shrink to 10 before resume
      File f = newTempFile("resume-badlen.bin");
      try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
        raf.setLength(20);
      }
      try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
        FileRandomAccessBuffer buf = new FileRandomAccessBuffer(raf, f, false);
        buf.close();
        try (RandomAccessFile raf2 = new RandomAccessFile(f, "rw")) {
          raf2.setLength(10);
        }

        // Act + Assert
        assertThrows(ResumeFailedException.class, () -> buf.onResume(null));
      }
    }

    @Test
    void onResume_whenOk_reopensAndAllowsIO() throws Exception {
      // Arrange
      File f = newTempFile("resume-ok.bin");
      try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(f, 8, false)) {
        buf.close();
        // Act
        buf.onResume(null);
        // Assert: perform a small write+read
        byte[] data = {42};
        buf.pwrite(0, data, 0, 1);
        byte[] out = new byte[1];
        buf.pread(0, out, 0, 1);
        assertArrayEquals(data, out);
        buf.free();
      }
    }
  }

  @Nested
  class SerializationTests {
    @Test
    void constructorDis_whenBadVersion_expectStorageFormatException() throws Exception {
      // Arrange
      try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
          DataOutputStream dos = new DataOutputStream(baos)) {
        dos.writeInt(999); // invalid VERSION (caller has already read MAGIC)
        // No more fields needed; constructor should fail on version check

        // Act + Assert
        try (DataInputStream dis =
            new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
          assertThrows(StorageFormatException.class, () -> new FileRandomAccessBuffer(dis));
        }
      }
    }

    @Test
    void constructorDis_whenNegativeLength_expectStorageFormatException() throws Exception {
      // Arrange
      File f = newTempFile("neg-length.bin");
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DataOutputStream dos = new DataOutputStream(baos);
      dos.writeInt(FileRandomAccessBuffer.VERSION); // version (MAGIC already consumed by caller)
      dos.writeUTF(f.toString());
      dos.writeBoolean(false); // readOnly
      dos.writeLong(-1L); // invalid length
      dos.writeBoolean(false); // secureDelete

      // Act + Assert
      DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
      assertThrows(StorageFormatException.class, () -> new FileRandomAccessBuffer(dis));
    }

    @Test
    void storeTo_whenRoundTripViaBucketTools_restoreEquivalent() throws Exception {
      // Arrange
      File f = newTempFile("roundtrip.bin");
      try (FileRandomAccessBuffer original = new FileRandomAccessBuffer(f, 16, false)) {
        original.setSecureDelete(true);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Act: write and then restore
        original.storeTo(dos);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
        LockableRandomAccessBuffer restored = BucketTools.restoreRAFFrom(dis, null, null, null);

        // Assert
        assertInstanceOf(FileRandomAccessBuffer.class, restored);
        assertEquals(original, restored);
        original.free();
        restored.free();
      }
    }
  }

  @Nested
  class MockitoInteractionTests {
    @Test
    void pread_whenUsingInjectedRaf_invokesSeekAndReadFully() throws Exception {
      // Arrange
      RandomAccessFile raf = mock(RandomAccessFile.class);
      when(raf.length()).thenReturn(64L);
      File f = newTempFile("mock-read.bin");
      try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(raf, f, false)) {
        byte[] out = new byte[4];

        // Stub readFully to simulate data fill
        doAnswer(
                inv -> {
                  byte[] arr = inv.getArgument(0);
                  int off = inv.getArgument(1);
                  int len = inv.getArgument(2);
                  for (int i = 0; i < len; i++) arr[off + i] = (byte) (100 + i);
                  return null;
                })
            .when(raf)
            .readFully(org.mockito.ArgumentMatchers.any(byte[].class), anyInt(), anyInt());

        // Act
        buf.pread(10, out, 0, out.length);
        // Assert
        verify(raf).seek(10);
        verify(raf).readFully(out, 0, out.length);
        assertArrayEquals(new byte[] {100, 101, 102, 103}, out);
        buf.free();
      }
    }

    @Test
    void pwrite_whenUsingInjectedRaf_invokesSeekAndWrite() throws Exception {
      // Arrange
      RandomAccessFile raf = mock(RandomAccessFile.class);
      when(raf.length()).thenReturn(64L);
      File f = newTempFile("mock-write.bin");
      try (FileRandomAccessBuffer buf = new FileRandomAccessBuffer(raf, f, false)) {
        byte[] data = {9, 8, 7, 6};
        // Act
        buf.pwrite(5, data, 0, data.length);
        // Assert
        verify(raf).seek(5);
        verify(raf).write(data, 0, data.length);
        buf.free();
      }
    }
  }
}
