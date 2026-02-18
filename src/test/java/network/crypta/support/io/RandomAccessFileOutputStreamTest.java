package network.crypta.support.io;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link RandomAccessFileOutputStream}.
 *
 * <p>Tests follow the AAA pattern and verify delegation behavior, error propagation, and boundary
 * conditions. Where useful, real I/O is used with a {@link TempDir} to validate byte-level
 * semantics; mocking is used to verify interactions and error paths.
 */
class RandomAccessFileOutputStreamTest {

  @TempDir Path tempDir;

  // -----------------------------
  // Constructor & basic behavior
  // -----------------------------

  @Test
  @DisplayName("constructor_withNullRaf_write_throwsNullPointerException")
  void constructorWithNullRafWriteThrowsNullPointerException() {
    // Arrange
    // Act & Assert (use TWR to satisfy resource-closure rule; close() NPE is suppressed)
    assertThrows(
        NullPointerException.class, RandomAccessFileOutputStreamTest::writeOneByteWithNullRaf);
  }

  private static void writeOneByteWithNullRaf() throws IOException {
    try (RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(null)) {
      out.write(1);
    }
  }

  // -----------------------------
  // write(int)
  // -----------------------------

  static Stream<Integer> singleByteValues() {
    return Stream.of(-1, 0, 0x7F, 0x80, 0xFF, 0x100, 0x1AB);
  }

  @ParameterizedTest
  @MethodSource("singleByteValues")
  @DisplayName("write_whenSingleInt_expectBytePersisted")
  void writeWhenSingleIntExpectBytePersisted(int value) throws Exception {
    // Arrange
    Path file = tempDir.resolve("single-byte.bin");
    try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw");
        RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf)) {
      // Act
      out.write(value);
    }

    // Assert
    byte[] bytes = Files.readAllBytes(file);
    assertThat("exactly one byte written", bytes.length, equalTo(1));
    assertThat("low 8 bits should be written", bytes[0], equalTo((byte) value));
  }

  @Test
  @DisplayName("write_whenCallsDelegate_writeByteInvokedOnce")
  void writeWhenCallsDelegateWriteByteInvokedOnce() throws Exception {
    // Arrange
    RandomAccessFile raf = mock(RandomAccessFile.class);
    try (RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf)) {
      // Act
      out.write(0xAB);
    }

    // Assert
    verify(raf, times(1)).writeByte(0xAB);
  }

  @Test
  @DisplayName("write_whenDelegateThrowsIOException_exceptionPropagates")
  void writeWhenDelegateThrowsIOExceptionExceptionPropagates() throws Exception {
    // Arrange
    RandomAccessFile raf = mock(RandomAccessFile.class);
    doThrow(new IOException("boom")).when(raf).writeByte(7);
    // Act & Assert
    IOException ex =
        assertThrows(
            IOException.class,
            () -> {
              try (RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf)) {
                out.write(7);
              }
            });
    assertThat(ex.getMessage(), equalTo("boom"));
  }

  // -----------------------------
  // write(byte[])
  // -----------------------------

  @Test
  @DisplayName("write_whenNullArray_expectNullPointerException")
  void writeWhenNullArrayExpectNullPointerException() throws Exception {
    // Arrange
    Path file = tempDir.resolve("null-array.bin");
    try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw");
        RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf)) {
      // Act & Assert
      assertThrows(NullPointerException.class, () -> out.write(null));
    }
  }

  @Test
  @DisplayName("write_whenEmptyArray_expectNoChangeAndNoError")
  void writeWhenEmptyArrayExpectNoChangeAndNoError() throws Exception {
    // Arrange
    Path file = tempDir.resolve("empty-array.bin");
    byte[] empty = new byte[0];
    try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw");
        RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf)) {
      // Act
      assertDoesNotThrow(() -> out.write(empty));
    }

    // Assert
    byte[] bytes = Files.readAllBytes(file);
    assertThat(bytes.length, equalTo(0));
  }

  @Test
  @DisplayName("write_whenCallsDelegate_writeArrayInvokedOnce")
  void writeWhenCallsDelegateWriteArrayInvokedOnce() throws Exception {
    // Arrange
    RandomAccessFile raf = mock(RandomAccessFile.class);
    byte[] data = new byte[] {1, 2, 3};
    try (RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf)) {
      // Act
      out.write(data);
    }

    // Assert
    verify(raf, times(1)).write(data);
  }

  @Test
  @DisplayName("write_whenArrayDelegateThrowsIOException_exceptionPropagates")
  void writeWhenArrayDelegateThrowsIOExceptionExceptionPropagates() throws Exception {
    // Arrange
    RandomAccessFile raf = mock(RandomAccessFile.class);
    byte[] data = new byte[] {9, 8};
    doThrow(new IOException("arr-io")).when(raf).write(data);
    // Act & Assert
    IOException ex =
        assertThrows(
            IOException.class,
            () -> {
              try (RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf)) {
                out.write(data);
              }
            });
    assertThat(ex.getMessage(), equalTo("arr-io"));
  }

  // -----------------------------
  // write(byte[], int, int)
  // -----------------------------

  @Test
  @DisplayName("write_withOffsetLen_whenNegativeIndices_expectIndexOutOfBoundsException")
  void writeWithOffsetLenWhenNegativeIndicesExpectIndexOutOfBoundsException() throws Exception {
    // Arrange
    Path file = tempDir.resolve("neg-idx.bin");
    byte[] data = new byte[] {10, 20, 30, 40};
    try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw");
        RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf)) {
      // Act & Assert
      assertAll(
          () -> assertThrows(IndexOutOfBoundsException.class, () -> out.write(data, -1, 1)),
          () -> assertThrows(IndexOutOfBoundsException.class, () -> out.write(data, 0, -1)));
    }
  }

  @Test
  @DisplayName("write_withOffsetLen_whenExceedsBounds_expectIndexOutOfBoundsException")
  void writeWithOffsetLenWhenExceedsBoundsExpectIndexOutOfBoundsException() throws Exception {
    // Arrange
    Path file = tempDir.resolve("oob-idx.bin");
    byte[] data = new byte[] {10, 20, 30, 40};
    try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw");
        RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf)) {
      // Act & Assert
      assertAll(
          () -> assertThrows(IndexOutOfBoundsException.class, () -> out.write(data, 5, 0)),
          () -> assertThrows(IndexOutOfBoundsException.class, () -> out.write(data, 3, 2)));
    }
  }

  @Test
  @DisplayName("write_withOffsetLen_whenCallsDelegate_invokedWithSameArgs")
  void writeWithOffsetLenWhenCallsDelegateInvokedWithSameArgs() throws Exception {
    // Arrange
    RandomAccessFile raf = mock(RandomAccessFile.class);
    byte[] data = new byte[] {5, 6, 7, 8};

    // Act
    try (RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf)) {
      out.write(data, 1, 2);
    }

    // Assert
    verify(raf, times(1)).write(data, 1, 2);
  }

  @Test
  @DisplayName("write_withOffsetLen_whenDelegateThrowsIOException_exceptionPropagates")
  void writeWithOffsetLenWhenDelegateThrowsIOExceptionExceptionPropagates() throws Exception {
    // Arrange
    RandomAccessFile raf = mock(RandomAccessFile.class);
    byte[] data = new byte[] {1, 2, 3, 4};
    doThrow(new IOException("oio")).when(raf).write(data, 1, 2);
    // Act & Assert
    IOException ex =
        assertThrows(
            IOException.class,
            () -> {
              try (RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf)) {
                out.write(data, 1, 2);
              }
            });
    assertThat(ex.getMessage(), equalTo("oio"));
  }

  // -----------------------------
  // close()
  // -----------------------------

  @Test
  @DisplayName("close_whenCallsDelegate_closeInvokedOnce")
  void closeWhenCallsDelegateCloseInvokedOnce() throws Exception {
    // Arrange
    RandomAccessFile raf = mock(RandomAccessFile.class);
    RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf);

    // Act
    out.close();

    // Assert
    verify(raf, times(1)).close();
  }

  @Test
  @DisplayName("write_afterClose_whenUsingRealFile_expectIOException")
  void writeAfterCloseWhenUsingRealFileExpectIOException() throws Exception {
    // Arrange
    Path file = tempDir.resolve("closed.bin");
    RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw");
    RandomAccessFileOutputStream out = new RandomAccessFileOutputStream(raf);
    out.close();

    // Act & Assert
    assertThrows(IOException.class, () -> out.write(1));
  }
}
