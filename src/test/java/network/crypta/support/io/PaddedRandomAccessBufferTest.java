package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.LockableRandomAccessBuffer.RAFLock;
import network.crypta.support.api.LockableRandomAccessBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100", "java:S5445", "java:S5443"})
class PaddedRandomAccessBufferTest {

  @Test
  void size_whenConstructed_returnsRealSize() {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    long realSize = 123L;

    // Act
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, realSize);

    // Assert
    assertEquals(realSize, padded.size());
  }

  static Object[][] ioHappyPathParams() {
    return new Object[][] {
      // fileOffset, length, realSize
      {0L, 0, 10L},
      {0L, 5, 10L},
      {5L, 5, 10L}, // exactly at the end
    };
  }

  @ParameterizedTest
  @MethodSource("ioHappyPathParams")
  void pread_whenWithinBounds_delegatesToInner(long fileOffset, int length, long realSize)
      throws IOException {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    byte[] buf = new byte[Math.max(1, length)];
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, realSize);

    // Act
    padded.pread(fileOffset, buf, 0, length);

    // Assert
    verify(inner).pread(fileOffset, buf, 0, length);
  }

  @ParameterizedTest
  @MethodSource("ioHappyPathParams")
  void pwrite_whenWithinBounds_delegatesToInner(long fileOffset, int length, long realSize)
      throws IOException {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    byte[] buf = new byte[Math.max(1, length)];
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, realSize);

    // Act
    padded.pwrite(fileOffset, buf, 0, length);

    // Assert
    verify(inner).pwrite(fileOffset, buf, 0, length);
  }

  @Test
  void pread_whenExceedsRealSize_throwsIOException() {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, 10);
    byte[] buf = new byte[4];

    // Act + Assert
    IOException ex = assertThrows(IOException.class, () -> padded.pread(8, buf, 0, 4)); // 8+4 > 10
    assertThat(ex.getMessage(), containsString("Length limit exceeded"));
    verifyNoInteractions(inner);
  }

  @Test
  void pwrite_whenExceedsRealSize_throwsIOException() {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, 10);
    byte[] buf = new byte[4];

    // Act + Assert
    IOException ex = assertThrows(IOException.class, () -> padded.pwrite(8, buf, 0, 4)); // 8+4 > 10
    assertThat(ex.getMessage(), containsString("Length limit exceeded"));
    verifyNoInteractions(inner);
  }

  @Test
  void pread_whenNegativeOffset_propagatesFromInner() throws IOException {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    doThrow(new IllegalArgumentException("neg"))
        .when(inner)
        .pread(eq(-1L), any(), anyInt(), anyInt());
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, 10);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> padded.pread(-1, new byte[1], 0, 1));
    verify(inner).pread(eq(-1L), any(), eq(0), eq(1));
  }

  @Test
  void pwrite_whenNegativeOffset_propagatesFromInner() throws IOException {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    doThrow(new IllegalArgumentException("neg"))
        .when(inner)
        .pwrite(eq(-1L), any(), anyInt(), anyInt());
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, 10);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> padded.pwrite(-1, new byte[1], 0, 1));
    verify(inner).pwrite(eq(-1L), any(), eq(0), eq(1));
  }

  @Test
  void pread_whenNullBuffer_propagatesFromInner() throws IOException {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    doThrow(new NullPointerException("buf"))
        .when(inner)
        .pread(anyLong(), isNull(), anyInt(), anyInt());
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, 10);

    // Act + Assert
    assertThrows(NullPointerException.class, () -> padded.pread(0, null, 0, 0));
  }

  @Test
  void pwrite_whenNullBuffer_propagatesFromInner() throws IOException {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    doThrow(new NullPointerException("buf"))
        .when(inner)
        .pwrite(anyLong(), isNull(), anyInt(), anyInt());
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, 10);

    // Act + Assert
    assertThrows(NullPointerException.class, () -> padded.pwrite(0, null, 0, 0));
  }

  @Test
  void close_whenCalled_delegatesToInner() {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, 1);

    // Act
    padded.close();

    // Assert
    verify(inner).close();
  }

  @Test
  void free_whenCalled_delegatesToInner() {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, 1);

    // Act
    padded.free();

    // Assert
    verify(inner).free();
  }

  @Test
  void lockOpen_whenCalled_delegatesAndReturnsSameLock() throws IOException {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    RAFLock lock = Mockito.mock(RAFLock.class);
    when(inner.lockOpen()).thenReturn(lock);
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, 1);

    // Act
    RAFLock returned = padded.lockOpen();

    // Assert
    assertSame(lock, returned);
    verify(inner).lockOpen();
  }

  @Test
  void onResume_whenCalled_delegatesToInner() throws ResumeFailedException {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    ClientContext ctx = mock(ClientContext.class);
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, 1);

    // Act
    padded.onResume(ctx);

    // Assert
    verify(inner).onResume(ctx);
  }

  @Test
  void storeTo_whenCalled_writesMagicThenSizeThenDelegates() throws IOException {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    long realSize = 42L;
    doAnswer(
            invocation -> {
              DataOutputStream out = invocation.getArgument(0);
              out.writeInt(0x12345678);
              return null;
            })
        .when(inner)
        .storeTo(org.mockito.ArgumentMatchers.any(DataOutputStream.class));
    PaddedRandomAccessBuffer padded = new PaddedRandomAccessBuffer(inner, realSize);
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    DataOutputStream dout = new DataOutputStream(bout);

    // Act
    padded.storeTo(dout);
    dout.flush();

    // Assert: MAGIC, realSize, then inner marker
    try (DataInputStream din = new DataInputStream(new ByteArrayInputStream(bout.toByteArray()))) {
      assertEquals(PaddedRandomAccessBuffer.MAGIC, din.readInt());
      assertEquals(realSize, din.readLong());
      assertEquals(0x12345678, din.readInt());
    }
  }

  @Nested
  @DisplayName("Deserialization constructor")
  class DeserializationConstructorTests {

    @Test
    void constructor_whenNegativeLength_throwsStorageFormatException() throws IOException {
      // Arrange: only the length is read before error
      ByteArrayOutputStream bout = new ByteArrayOutputStream();
      DataOutputStream dout = new DataOutputStream(bout);
      dout.writeLong(-1L); // negative realSize
      dout.flush();

      try (DataInputStream din =
          new DataInputStream(new ByteArrayInputStream(bout.toByteArray()))) {
        // Act + Assert
        assertThrows(
            StorageFormatException.class,
            () ->
                new PaddedRandomAccessBuffer(
                    din,
                    mock(FilenameGenerator.class),
                    mock(PersistentFileTracker.class),
                    mock(MasterSecret.class)));
      }
    }

    @Test
    void constructor_whenRealSizeGreaterThanInner_throwsResumeFailed() throws Exception {
      // Arrange: build a stream = [realSize][inner RAF (FileRandomAccessBuffer)]
      File tmp = File.createTempFile("padded-raf-test", ".bin");
      tmp.deleteOnExit();
      try (FileOutputStream fos = new FileOutputStream(tmp)) {
        fos.write(new byte[10]); // ensure file length >= 10
      }

      try (DataInputStream din = buildPaddedRafStream(12L, tmp)) {
        // Act + Assert
        assertThrows(
            ResumeFailedException.class,
            () ->
                new PaddedRandomAccessBuffer(
                    din,
                    mock(FilenameGenerator.class),
                    mock(PersistentFileTracker.class),
                    mock(MasterSecret.class)));
      }
    }

    @Test
    void constructor_whenValid_buildsAndEnforcesPadding() throws Exception {
      // Arrange: inner size 10, realSize 6
      File tmp = File.createTempFile("padded-raf-test", ".bin");
      tmp.deleteOnExit();
      try (FileOutputStream fos = new FileOutputStream(tmp)) {
        fos.write(new byte[10]);
      }

      try (DataInputStream din = buildPaddedRafStream(6L, tmp)) {
        // Act
        PaddedRandomAccessBuffer padded =
            new PaddedRandomAccessBuffer(
                din,
                mock(FilenameGenerator.class),
                mock(PersistentFileTracker.class),
                mock(MasterSecret.class));

        // Assert
        assertEquals(6L, padded.size());

        // Also verify bound is enforced at runtime
        byte[] b = new byte[4];
        assertDoesNotThrow(() -> padded.pread(2, b, 0, 4)); // 2+4 == 6 OK
        assertThrows(IOException.class, () -> padded.pread(3, b, 0, 4)); // 3+4 > 6
      }
    }
  }

  private static DataInputStream buildPaddedRafStream(long realSize, File innerFile)
      throws IOException {
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try (DataOutputStream dout = new DataOutputStream(bout)) {
      dout.writeLong(realSize);
      // Inner RAF serialization: magic then constructor-specific payload
      dout.writeInt(FileRandomAccessBuffer.MAGIC);
      dout.writeInt(1); // VERSION for FileRandomAccessBuffer
      dout.writeUTF(innerFile.getAbsolutePath());
      dout.writeBoolean(true); // readOnly in tests
      dout.writeLong(innerFile.length()); // inner length equals actual file length
      dout.writeBoolean(false); // secureDelete default
    }
    return new DataInputStream(new ByteArrayInputStream(bout.toByteArray()));
  }

  @Test
  void equalsAndHashCode_whenSameInnerAndSize_areEqual() {
    // Arrange
    LockableRandomAccessBuffer inner = mock(LockableRandomAccessBuffer.class);
    PaddedRandomAccessBuffer a = new PaddedRandomAccessBuffer(inner, 7);
    PaddedRandomAccessBuffer b = new PaddedRandomAccessBuffer(inner, 7);

    // Act + Assert
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void equals_whenDifferentInnerOrSize_areNotEqual() {
    // Arrange
    LockableRandomAccessBuffer inner1 = mock(LockableRandomAccessBuffer.class);
    LockableRandomAccessBuffer inner2 = mock(LockableRandomAccessBuffer.class);
    PaddedRandomAccessBuffer a = new PaddedRandomAccessBuffer(inner1, 7);
    PaddedRandomAccessBuffer b = new PaddedRandomAccessBuffer(inner2, 7);
    PaddedRandomAccessBuffer c = new PaddedRandomAccessBuffer(inner1, 8);

    // Act + Assert
    assertNotEquals(b, a);
    assertNotEquals(c, a);
    assertNotEquals(new Object(), a);
    assertNotEquals(null, a);
    //noinspection EqualsWithItself
    assertEquals(a, a); // reflexive
  }
}
