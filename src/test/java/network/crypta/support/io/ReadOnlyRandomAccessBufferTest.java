package network.crypta.support.io;

import java.io.*;

import java.nio.file.Files;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.LockableRandomAccessBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReadOnlyRandomAccessBufferTest {

  @Test
  @DisplayName("pwrite_whenCalled_expectIOException")
  void pwriteWhenCalledExpectIOException() {
    // Arrange
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    ReadOnlyRandomAccessBuffer ro = new ReadOnlyRandomAccessBuffer(underlying);

    // Act + Assert
    IOException ex =
        assertThrows(
            IOException.class, () -> ro.pwrite(0L, new byte[1], 0, 1), "Must throw on writes");
    assertEquals("Read only", ex.getMessage());
    verifyNoInteractions(underlying);
  }

  @Test
  @DisplayName("size_whenDelegates_expectUnderlyingValue")
  void sizeWhenDelegatesExpectUnderlyingValue() {
    // Arrange
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    when(underlying.size()).thenReturn(12345L);
    ReadOnlyRandomAccessBuffer ro = new ReadOnlyRandomAccessBuffer(underlying);

    // Act
    long size = ro.size();

    // Assert
    assertEquals(12345L, size);
    verify(underlying).size();
    verifyNoMoreInteractions(underlying);
  }

  @Test
  @DisplayName("pread_whenDelegates_expectUnderlyingCalled")
  void preadWhenDelegatesExpectUnderlyingCalled() throws IOException {
    // Arrange
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    ReadOnlyRandomAccessBuffer ro = new ReadOnlyRandomAccessBuffer(underlying);
    byte[] buf = new byte[8];

    // Act
    ro.pread(7L, buf, 2, 3);

    // Assert
    verify(underlying).pread(7L, buf, 2, 3);
    verifyNoMoreInteractions(underlying);
  }

  @Test
  @DisplayName("pread_whenUnderlyingThrows_expectPropagated")
  void preadWhenUnderlyingThrowsExpectPropagated() throws IOException {
    // Arrange
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    IOException boom = new IOException("boom");
    doThrow(boom).when(underlying).pread(anyLong(), any(), anyInt(), anyInt());
    ReadOnlyRandomAccessBuffer ro = new ReadOnlyRandomAccessBuffer(underlying);

    // Act + Assert
    byte[] buf = new byte[4];
    IOException ex = assertThrows(IOException.class, () -> ro.pread(1, buf, 0, 4));
    assertSame(boom, ex);
    verify(underlying).pread(1L, buf, 0, 4);
  }

  @Test
  @DisplayName("close_whenCalled_expectDelegates")
  void closeWhenCalledExpectDelegates() {
    // Arrange
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    ReadOnlyRandomAccessBuffer ro = new ReadOnlyRandomAccessBuffer(underlying);

    // Act
    ro.close();

    // Assert
    verify(underlying).close();
    verifyNoMoreInteractions(underlying);
  }

  @Test
  @DisplayName("free_whenCalled_expectDelegates")
  void freeWhenCalledExpectDelegates() {
    // Arrange
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    ReadOnlyRandomAccessBuffer ro = new ReadOnlyRandomAccessBuffer(underlying);

    // Act
    ro.free();

    // Assert
    verify(underlying).free();
    verifyNoMoreInteractions(underlying);
  }

  @Test
  @DisplayName("lockOpen_whenCalled_expectReturnsUnderlyingLock")
  void lockOpenWhenCalledExpectReturnsUnderlyingLock() throws IOException {
    // Arrange
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    LockableRandomAccessBuffer.RAFLock lock =
        new LockableRandomAccessBuffer.RAFLock() {
          @Override
          protected void innerUnlock() {
            // no-op
          }
        };
    when(underlying.lockOpen()).thenReturn(lock);
    ReadOnlyRandomAccessBuffer ro = new ReadOnlyRandomAccessBuffer(underlying);

    // Act
    LockableRandomAccessBuffer.RAFLock got = ro.lockOpen();

    // Assert
    assertSame(lock, got);
    verify(underlying).lockOpen();
    verifyNoMoreInteractions(underlying);
  }

  @Test
  @DisplayName("onResume_whenCalled_expectDelegates")
  void onResumeWhenCalledExpectDelegates() throws ResumeFailedException {
    // Arrange
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    ClientContext ctx = mock(ClientContext.class);
    ReadOnlyRandomAccessBuffer ro = new ReadOnlyRandomAccessBuffer(underlying);

    // Act
    ro.onResume(ctx);

    // Assert
    verify(underlying).onResume(ctx);
    verifyNoMoreInteractions(underlying);
  }

  @Test
  @DisplayName("storeTo_whenCalled_expectWritesMagicThenDelegates")
  void storeToWhenCalledExpectWritesMagicThenDelegates() throws IOException {
    // Arrange
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    AtomicInteger sentinel = new AtomicInteger(0xCAFEBABE);
    doAnswer(
            inv -> {
              DataOutputStream out = inv.getArgument(0, DataOutputStream.class);
              out.writeInt(sentinel.get());
              return null;
            })
        .when(underlying)
        .storeTo(any(DataOutputStream.class));
    ReadOnlyRandomAccessBuffer ro = new ReadOnlyRandomAccessBuffer(underlying);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);

    // Act
    ro.storeTo(dos);
    dos.flush();
    byte[] bytes = baos.toByteArray();

    // Assert
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      assertEquals(ReadOnlyRandomAccessBuffer.MAGIC, dis.readInt());
      assertEquals(sentinel.get(), dis.readInt());
      assertEquals(-1, dis.read()); // nothing extra
    }
    verify(underlying).storeTo(any(DataOutputStream.class));
    verifyNoMoreInteractions(underlying);
  }

  @Test
  @DisplayName("constructor_withDataInputStream_expectRestoresUnderlying")
  void constructorWithDataInputStreamExpectRestoresUnderlying()
      throws Exception { // IOException, StorageFormatException, ResumeFailedException
    // Arrange: build a valid underlying FileRandomAccessBuffer serialization
    File tmp = newSecureTempFile();
    FilenameGenerator fg = mock(FilenameGenerator.class);
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    MasterSecret master = mock(MasterSecret.class);

    LockableRandomAccessBuffer restored;
    try (DataInputStream dis = buildReadOnlyWrappedStream(tmp)) {
      // Act: go through the real restore path
      restored = BucketTools.restoreRAFFrom(dis, fg, pft, master);
    }

    // Assert
    assertNotNull(restored);
    ReadOnlyRandomAccessBuffer ro = assertInstanceOf(ReadOnlyRandomAccessBuffer.class, restored);
    // Underlying is a FileRandomAccessBuffer based on tmp; read-only wrapper must still reject
    // writes
    IOException ex = assertThrows(IOException.class, () -> ro.pwrite(0, new byte[0], 0, 0));
    assertEquals("Read only", ex.getMessage());
  }

  private static final String TEMP_PREFIX = "ro-raf-";
  private static final String TEMP_SUFFIX = ".bin";

  private static File newSecureTempFile() throws IOException {
    File dir = new File("build/test-tmp/ReadOnlyRandomAccessBufferTest");
    if (!(dir.mkdirs() || dir.isDirectory())) {
      throw new IOException("Failed to create secure test directory: " + dir);
    }
    return Files.createTempFile(dir.toPath(), TEMP_PREFIX, TEMP_SUFFIX).toFile();
  }

  private static DataInputStream buildReadOnlyWrappedStream(File tmp) throws IOException {
    ByteArrayOutputStream baosUnderlying = new ByteArrayOutputStream();
    try (FileRandomAccessBuffer realUnderlying = new FileRandomAccessBuffer(tmp, true);
        DataOutputStream udos = new DataOutputStream(baosUnderlying)) {
      // Only write the underlying's own serialization (which already includes its MAGIC)
      realUnderlying.storeTo(udos);
    }
    byte[] underlyingBytes = baosUnderlying.toByteArray();

    // Prepend ReadOnlyRandomAccessBuffer.MAGIC so BucketTools dispatches to this class first
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(ReadOnlyRandomAccessBuffer.MAGIC);
      dos.write(underlyingBytes);
    }
    return new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
  }

  // ----------------------- equals/hashCode -----------------------

  static Object[][] equalsProvider() {
    LockableRandomAccessBuffer u1 = mock(LockableRandomAccessBuffer.class);
    LockableRandomAccessBuffer u2 = mock(LockableRandomAccessBuffer.class);
    return new Object[][] {
      // same instance
      {new ReadOnlyRandomAccessBuffer(u1), new ReadOnlyRandomAccessBuffer(u1), true},
      // different underlying instances
      {new ReadOnlyRandomAccessBuffer(u1), new ReadOnlyRandomAccessBuffer(u2), false}
    };
  }

  @ParameterizedTest(name = "equals param case {index}")
  @MethodSource("equalsProvider")
  @DisplayName("equals_whenVariousUnderlying_expectOutcome")
  void equalsWhenVariousUnderlyingExpectOutcome(
      ReadOnlyRandomAccessBuffer a, ReadOnlyRandomAccessBuffer b, boolean expectedEqual) {
    // Act + Assert
    assertEquals(expectedEqual, a.equals(b));
    assertEquals(expectedEqual, b.equals(a));
    if (expectedEqual) {
      assertEquals(a.hashCode(), b.hashCode());
    }
  }

  @Test
  @DisplayName("equals_whenNullOrDifferentClass_expectFalse")
  void equalsWhenNullOrDifferentClassExpectFalse() {
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    ReadOnlyRandomAccessBuffer ro = new ReadOnlyRandomAccessBuffer(underlying);
    // Prefer using assertion helpers instead of calling equals(null) directly
    assertNotEquals(null, ro);
    // Different runtime class should not be equal due to strict getClass() check.
    assertNotEquals(ro, mock(LockableRandomAccessBuffer.class));
  }
}
