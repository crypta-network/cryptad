package network.crypta.support.io;

import java.io.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.stream.Stream;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.LockableRandomAccessBuffer.RAFLock;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import static org.hamcrest.MatcherAssert.assertThat;

@Tag("unit")
@SuppressWarnings("java:S100") // Keep method_whenCondition_expectOutcome naming per project style
class PooledFileRandomAccessBufferTest {

  @TempDir File tempDir;

  @AfterEach
  void tearDown() {
    // Nothing to clean beyond @TempDir; guard in case a test left files locked
  }

  // ------------------------------------------------------------
  // Constructors and size()
  // ------------------------------------------------------------

  @Test
  void size_whenConstructedWithInitialContents_matchesSize() throws Exception {
    // Arrange
    File f = new File(tempDir, "init.bin");
    byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);

    // Act
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, data, 0, data.length, -1L, false, /* readOnly= */ false);

    // Assert
    assertEquals(data.length, p.size());
    p.close();

    // verify file contents written
    byte[] onDisk = Files.readAllBytes(f.toPath());
    assertArrayEquals(data, onDisk);
  }

  @Test
  void size_whenConstructedFromExistingFile_reflectsCurrentLength() throws Exception {
    // Arrange
    File f = new File(tempDir, "existing.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(64);
    }

    // Use the internal-test constructor to avoid preallocation and to inject a tracker
    PooledFileRandomAccessBuffer.FDTracker tracker = new PooledFileRandomAccessBuffer.FDTracker(8);

    // Act
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, /* readOnly= */ false, /* forceLength= */ -1, -1L, false, tracker);

    // Assert
    assertEquals(64, p.size());
    p.close();
  }

  // ------------------------------------------------------------
  // pwrite / pread basic behavior
  // ------------------------------------------------------------

  @Test
  void pwrite_whenWithinBounds_writesAndCanBeReadBack() throws Exception {
    // Arrange
    File f = new File(tempDir, "rw.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(32);
    }
    PooledFileRandomAccessBuffer.FDTracker tracker = new PooledFileRandomAccessBuffer.FDTracker(4);
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(f, false, -1, -1L, false, tracker);
    byte[] payload = new byte[] {1, 2, 3, 4, 5};

    // Act
    p.pwrite(10, payload, 0, payload.length);

    // Assert via pread
    byte[] buf = new byte[5];
    p.pread(10, buf, 0, buf.length);
    assertArrayEquals(payload, buf);
    p.close();
  }

  @Test
  void pwrite_whenReadOnly_expectIOException() throws Exception {
    // Arrange
    File f = new File(tempDir, "readonly.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(8);
    }
    PooledFileRandomAccessBuffer.FDTracker tracker = new PooledFileRandomAccessBuffer.FDTracker(2);
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, /* readOnly= */ true, /* forceLength= */ -1, -1L, false, tracker);

    // Act + Assert
    IOException ex =
        assertThrows(IOException.class, () -> p.pwrite(0, new byte[] {9}, 0, 1), "Read only");
    assertThat(ex.getMessage(), containsString("Read only"));
    p.close();
  }

  static Stream<long[]> pwriteOutOfBoundsCases() {
    return Stream.of(
        new long[] {0, 9}, // offset=0, len=9 > size 8
        new long[] {7, 2}, // tail overrun
        new long[] {8, 1} // writing at EOF with len>0
        );
  }

  @ParameterizedTest
  @MethodSource("pwriteOutOfBoundsCases")
  void pwrite_whenExceedsLength_expectIOException(long[] params) throws Exception {
    // Arrange
    long offset = params[0];
    int len = (int) params[1];
    File f = new File(tempDir, "bounds.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(8);
    }
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, false, -1, -1L, false, new PooledFileRandomAccessBuffer.FDTracker(1));

    // Act + Assert
    IOException ex = assertThrows(IOException.class, () -> p.pwrite(offset, new byte[len], 0, len));
    assertThat(ex.getMessage(), containsString("Length limit exceeded"));
    p.close();
  }

  @Test
  void pread_whenNegativeOffset_expectIllegalArgumentException() throws Exception {
    File f = new File(tempDir, "neg.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(4);
    }
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, false, -1, -1L, false, new PooledFileRandomAccessBuffer.FDTracker(1));

    assertThrows(IllegalArgumentException.class, () -> p.pread(-1, new byte[1], 0, 1));
    p.close();
  }

  @Test
  void pwrite_whenNegativeOffset_expectIllegalArgumentException() throws Exception {
    File f = new File(tempDir, "negw.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(4);
    }
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, false, -1, -1L, false, new PooledFileRandomAccessBuffer.FDTracker(1));

    assertThrows(IllegalArgumentException.class, () -> p.pwrite(-1, new byte[1], 0, 1));
    p.close();
  }

  // ------------------------------------------------------------
  // Locking and pooling
  // ------------------------------------------------------------

  @Test
  void lockOpen_whenPoolLimitExceeded_closesOlderRAF() throws Exception {
    // Arrange: tracker allows only 1 open FD
    PooledFileRandomAccessBuffer.FDTracker tracker = new PooledFileRandomAccessBuffer.FDTracker(1);

    File f1 = new File(tempDir, "a.bin");
    File f2 = new File(tempDir, "b.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f1, "rw")) {
      raf.setLength(16);
    }
    try (RandomAccessFile raf = new RandomAccessFile(f2, "rw")) {
      raf.setLength(16);
    }

    PooledFileRandomAccessBuffer a =
        new PooledFileRandomAccessBuffer(f1, false, -1, -1L, false, tracker);
    PooledFileRandomAccessBuffer b =
        new PooledFileRandomAccessBuffer(f2, false, -1, -1L, false, tracker);

    // Initially: lock/unlock A, making it closable in the pool
    RAFLock la = a.lockOpen();
    la.unlock();
    assertTrue(a.isOpen(), "A should remain open after unlock");
    assertThat(tracker.getClosableFDs(), greaterThanOrEqualTo(1));

    // Act: lock B; pool must close A to free a slot
    RAFLock lb = b.lockOpen();

    // Assert: A got closed by the pool, B is open
    assertFalse(a.isOpen(), "A must be closed by the pool");
    assertTrue(b.isOpen(), "B should be open after acquiring lock");

    lb.unlock();
    a.close();
    b.close();
  }

  @Test
  void close_whenLocked_expectIllegalStateException() throws Exception {
    File f = new File(tempDir, "locked.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(8);
    }
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, false, -1, -1L, false, new PooledFileRandomAccessBuffer.FDTracker(1));

    RAFLock l = p.lockOpen();
    assertThrows(IllegalStateException.class, p::close);
    l.unlock();
    p.close();
  }

  @Test
  void lockOpen_afterClose_expectIOException() throws Exception {
    File f = new File(tempDir, "closed.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(8);
    }
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, false, -1, -1L, false, new PooledFileRandomAccessBuffer.FDTracker(1));

    p.close();
    assertThrows(IOException.class, p::lockOpen);
  }

  @Test
  void lockOpen_unlockTwice_expectIllegalStateException() throws Exception {
    File f = new File(tempDir, "doubleUnlock.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(8);
    }
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, false, -1, -1L, false, new PooledFileRandomAccessBuffer.FDTracker(1));

    RAFLock l = p.lockOpen();
    l.unlock();
    assertThrows(IllegalStateException.class, l::unlock);
    p.close();
  }

  // ------------------------------------------------------------
  // free() and deletion flags
  // ------------------------------------------------------------

  @Test
  void free_whenDeleteOnFreeFalse_retainsFile() throws Exception {
    File f = new File(tempDir, "keep.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(1);
    }
    try (PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f,
            false,
            -1,
            -1L,
            /* deleteOnFree= */ false,
            new PooledFileRandomAccessBuffer.FDTracker(1))) {
      // Act
      p.free();
    }

    // Assert
    assertTrue(f.exists());
  }

  @Test
  void free_whenDeleteOnFreeTrueWithoutSecureDelete_deletesFile() throws Exception {
    File f = new File(tempDir, "del.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(1);
    }
    try (PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f,
            false,
            -1,
            -1L,
            /* deleteOnFree= */ true,
            new PooledFileRandomAccessBuffer.FDTracker(1))) {
      // Act
      p.free();
    }

    // Assert
    assertFalse(f.exists());
  }

  @Test
  void free_whenSecureDeleteTrue_deletesFile() throws Exception {
    File f = new File(tempDir, "sdel.bin");
    Files.write(f.toPath(), new byte[] {42});
    try (PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f,
            false,
            -1,
            -1L,
            /* deleteOnFree= */ true,
            new PooledFileRandomAccessBuffer.FDTracker(1))) {
      p.setSecureDelete(true);

      // Act
      p.free();
    }

    // Assert
    assertFalse(f.exists());
  }

  // ------------------------------------------------------------
  // storeTo/load round-trips and resume behavior
  // ------------------------------------------------------------

  @Test
  void storeToAndLoad_whenPersistentTempIdMinusOne_roundTripsProperties() throws Exception {
    // Arrange
    File f = new File(tempDir, "round.bin");
    byte[] content = new byte[3];
    Files.write(f.toPath(), content);
    PooledFileRandomAccessBuffer orig =
        new PooledFileRandomAccessBuffer(
            f, false, -1, -1L, true, new PooledFileRandomAccessBuffer.FDTracker(4));

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      orig.storeTo(dos);
    }

    // Act: read back; the reader expects the MAGIC to have been consumed already
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
    assertEquals(PooledFileRandomAccessBuffer.MAGIC, dis.readInt());
    PooledFileRandomAccessBuffer copy =
        new PooledFileRandomAccessBuffer(
            dis, mock(FilenameGenerator.class), mock(PersistentFileTracker.class));

    // Assert
    assertEquals(orig.size(), copy.size());
    assertEquals(orig, copy);
  }

  @Test
  void load_whenPersistentTempFileMissingButMoved_registersWithTrackerAndUsesNewFile()
      throws Exception {
    // Arrange: create a serialized descriptor that references a missing file with a temp ID
    File original = new File(tempDir, "missing.bin");
    long tempId = 0xABCDL;
    ByteArrayOutputStream baos = getByteArrayOutputStream(original, tempId);

    // Prepare mocks: original does not exist; generator resolves a different existing file
    FilenameGenerator fg = mock(FilenameGenerator.class);
    PersistentFileTracker tracker = mock(PersistentFileTracker.class);
    File moved = new File(tempDir, "tmp-" + Long.toHexString(tempId));
    Files.write(moved.toPath(), new byte[0]); // ensure it exists
    when(fg.getFilename(tempId)).thenReturn(moved);

    // Act
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
    assertEquals(PooledFileRandomAccessBuffer.MAGIC, dis.readInt()); // consume magic
    PooledFileRandomAccessBuffer p = new PooledFileRandomAccessBuffer(dis, fg, tracker);

    // Assert
    verify(tracker, times(1)).register(moved);
    assertNotNull(p.file);
    assertEquals(moved.getCanonicalPath(), p.file.getCanonicalPath());
  }

  private static @NotNull ByteArrayOutputStream getByteArrayOutputStream(File original, long tempId)
      throws IOException {
    boolean readOnly = false;
    boolean deleteOnFree = true;
    boolean secureDelete = true;
    long length = 0;
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(PooledFileRandomAccessBuffer.MAGIC);
      dos.writeInt(1); // VERSION
      dos.writeUTF(original.toString());
      dos.writeBoolean(readOnly);
      dos.writeLong(length);
      dos.writeLong(tempId);
      dos.writeBoolean(deleteOnFree);
      dos.writeBoolean(secureDelete);
    }
    return baos;
  }

  @Test
  void load_whenPersistentTempFileMissingAndNotFound_throwsResumeFailedException()
      throws Exception {
    // Arrange: serialized descriptor referencing a missing file with temp ID
    File original = new File(tempDir, "missing2.bin");
    long tempId = 1234L;
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(PooledFileRandomAccessBuffer.MAGIC);
      dos.writeInt(1);
      dos.writeUTF(original.toString());
      dos.writeBoolean(false);
      dos.writeLong(0L);
      dos.writeLong(tempId);
      dos.writeBoolean(false);
    }

    FilenameGenerator fg = mock(FilenameGenerator.class);
    when(fg.getFilename(tempId)).thenReturn(new File(tempDir, "absent-" + tempId));
    when(fg.maybeMove(org.mockito.ArgumentMatchers.any(File.class), anyLong()))
        .thenAnswer(invocation -> invocation.getArgument(0));

    // Act + Assert
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
    assertEquals(PooledFileRandomAccessBuffer.MAGIC, dis.readInt());
    assertThrows(
        ResumeFailedException.class,
        () -> new PooledFileRandomAccessBuffer(dis, fg, mock(PersistentFileTracker.class)));
  }

  @Test
  void onResume_whenFileMissing_throwsResumeFailedException() throws Exception {
    // Arrange
    File f = new File(tempDir, "gone.bin");
    Files.write(f.toPath(), new byte[] {1, 2});
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, false, -1, -1L, false, new PooledFileRandomAccessBuffer.FDTracker(1));
    p.close();
    java.nio.file.Files.delete(f.toPath());
    assertFalse(java.nio.file.Files.exists(f.toPath()));

    // Act + Assert
    assertThrows(ResumeFailedException.class, () -> p.onResume(mock(ClientContext.class)));
  }

  @Test
  void onResume_whenLengthGreaterThanOnDisk_throwsResumeFailedException() throws Exception {
    // Arrange: create a file and shrink it after creating the RAF wrapper
    File f = new File(tempDir, "shorter.bin");
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(10);
    }
    PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, false, -1, -1L, false, new PooledFileRandomAccessBuffer.FDTracker(1));
    p.close();
    try (RandomAccessFile raf = new RandomAccessFile(f, "rw")) {
      raf.setLength(5); // shrink on disk; p.length still 10
    }

    // Act + Assert
    assertThrows(ResumeFailedException.class, () -> p.onResume(mock(ClientContext.class)));
  }

  @Test
  void onResume_whenPersistentTempIdNonNegative_registersWithTracker() throws Exception {
    // Arrange
    File f = new File(tempDir, "resume.bin");
    Files.write(f.toPath(), new byte[] {0});
    long tempId = 42L;
    try (PooledFileRandomAccessBuffer p =
        new PooledFileRandomAccessBuffer(
            f, false, -1, tempId, false, new PooledFileRandomAccessBuffer.FDTracker(1))) {
      ClientContext ctx = mock(ClientContext.class);
      PersistentFileTracker tracker = mock(PersistentFileTracker.class);
      when(ctx.getPersistentFileTracker()).thenReturn(tracker);

      // Act
      p.onResume(ctx);

      // Assert
      verify(tracker, times(1)).register(f);
    }
  }

  // ------------------------------------------------------------
  // equals/hashCode
  // ------------------------------------------------------------

  @Test
  void equals_whenSameProperties_expectEqual() throws Exception {
    File f = new File(tempDir, "eq.bin");
    Files.write(f.toPath(), new byte[] {1});
    PooledFileRandomAccessBuffer.FDTracker tracker = new PooledFileRandomAccessBuffer.FDTracker(2);
    PooledFileRandomAccessBuffer a =
        new PooledFileRandomAccessBuffer(f, false, -1, -1L, true, tracker);
    PooledFileRandomAccessBuffer b =
        new PooledFileRandomAccessBuffer(f, false, -1, -1L, true, tracker);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    a.close();
    b.close();
  }

  @Test
  void equals_whenDifferentFlags_expectNotEqual() throws Exception {
    File f = new File(tempDir, "neq.bin");
    Files.write(f.toPath(), new byte[] {1});
    PooledFileRandomAccessBuffer a =
        new PooledFileRandomAccessBuffer(
            f,
            /* readOnly= */ false,
            -1,
            -1L,
            /* deleteOnFree= */ true,
            new PooledFileRandomAccessBuffer.FDTracker(1));
    PooledFileRandomAccessBuffer b =
        new PooledFileRandomAccessBuffer(
            f,
            /* readOnly= */ true,
            -1,
            -1L,
            /* deleteOnFree= */ false,
            new PooledFileRandomAccessBuffer.FDTracker(1));
    assertNotEquals(a, b);
    a.close();
    b.close();
  }
}
