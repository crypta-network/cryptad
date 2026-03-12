package network.crypta.support.compress;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class DecompressorThreadManagerTest {

  PipedOutputStream sourceOut; // closed in tearDown when allocated

  @AfterEach
  void tearDown() {
    if (sourceOut != null) {
      try {
        sourceOut.close();
      } catch (IOException _) {
        // Best-effort cleanup in tests: stream may already be closed.
      }
      sourceOut = null;
    }
  }

  @Test
  @DisplayName("constructor_whenNullInputStream_expectIOException")
  void constructor_whenNullInputStream_expectIOException() {
    // Arrange
    List<Compressor> decompressors = new ArrayList<>();

    // Act + Assert
    IOException ex =
        assertThrows(
            IOException.class,
            () -> new DecompressorThreadManager(null, decompressors, /*maxLen*/ 1024));
    assertEquals("Input stream may not be null", ex.getMessage());
  }

  @Test
  @DisplayName("constructor_whenNullDecompressors_expectNullPointerException")
  void constructor_whenNullDecompressors_expectNullPointerException() throws Exception {
    // Arrange
    PipedInputStream in = new PipedInputStream();
    sourceOut = new PipedOutputStream(in);

    // Act + Assert
    //noinspection ConstantConditions  -- intentional null to verify constructor null-handling
    assertThrows(NullPointerException.class, () -> new DecompressorThreadManager(in, null, 1));
  }

  @Test
  @DisplayName("execute_whenNoDecompressors_returnsOriginalStreamAndFinishes")
  void execute_whenNoDecompressors_returnsOriginalStreamAndFinishes() throws Throwable {
    // Arrange
    PipedInputStream in = new PipedInputStream();
    sourceOut = new PipedOutputStream(in);
    List<Compressor> decompressors = new ArrayList<>();
    DecompressorThreadManager manager = new DecompressorThreadManager(in, decompressors, 1024);

    // Act
    PipedInputStream result = manager.execute();

    // Write some bytes to the original input; since there are no decompressors the same bytes
    // must be available on the returned stream.
    byte[] payload = "hello crypta".getBytes(StandardCharsets.UTF_8);
    sourceOut.write(payload);
    sourceOut.flush();
    sourceOut.close();
    sourceOut = null; // closed

    byte[] read = result.readAllBytes();

    // Assert
    assertArrayEquals(payload, read);
    assertDoesNotThrow(manager::waitFinished);
    assertNull(manager.getError());
  }

  @Test
  @DisplayName("execute_whenSingleDecompressor_successfulDecompression")
  void execute_whenSingleDecompressor_successfulDecompression() throws Throwable {
    // Arrange
    PipedInputStream in = new PipedInputStream();
    sourceOut = new PipedOutputStream(in);

    Compressor mockDecompressor = mock(Compressor.class);
    // Pass-through decompression: copy input to output
    doAnswer(
            invocation -> {
              InputStream is = invocation.getArgument(0);
              OutputStream os = invocation.getArgument(1);
              byte[] buf = is.readAllBytes();
              os.write(buf);
              os.flush();
              return (long) buf.length;
            })
        .when(mockDecompressor)
        .decompress(any(InputStream.class), any(java.io.OutputStream.class), anyLong(), anyLong());

    List<Compressor> decompressors = new ArrayList<>(List.of(mockDecompressor));
    DecompressorThreadManager manager = new DecompressorThreadManager(in, decompressors, 64);

    // Act
    PipedInputStream result = manager.execute();

    byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
    sourceOut.write(payload);
    sourceOut.flush();
    sourceOut.close();
    sourceOut = null;

    byte[] out = result.readAllBytes();
    manager.waitFinished();

    // Assert
    assertArrayEquals(payload, out, "Pass-through decompressor must preserve data");
    verify(mockDecompressor, atLeastOnce())
        .decompress(any(InputStream.class), any(java.io.OutputStream.class), eq(64L), eq(256L));
    assertNull(manager.getError());
  }

  @Test
  @DisplayName("execute_whenMultipleDecompressors_applyInReverseOrder")
  void execute_whenMultipleDecompressors_applyInReverseOrder() throws Throwable {
    // Arrange
    PipedInputStream in = new PipedInputStream();
    sourceOut = new PipedOutputStream(in);

    Compressor a = mock(Compressor.class); // innermost (last to execute)
    Compressor b = mock(Compressor.class); // outermost (first to execute)

    // Decompressor 'a': wraps data with "A[" + data + "]"
    doAnswer(
            invocation -> {
              InputStream is = invocation.getArgument(0);
              OutputStream os = invocation.getArgument(1);
              byte[] inBytes = is.readAllBytes();
              byte[] res =
                  ("A[" + new String(inBytes, StandardCharsets.UTF_8) + "]")
                      .getBytes(StandardCharsets.UTF_8);
              os.write(res);
              os.flush();
              return (long) res.length;
            })
        .when(a)
        .decompress(any(InputStream.class), any(java.io.OutputStream.class), anyLong(), anyLong());

    // Decompressor 'b': wraps data with "B{" + data + "}"
    doAnswer(
            invocation -> {
              InputStream is = invocation.getArgument(0);
              OutputStream os = invocation.getArgument(1);
              byte[] inBytes = is.readAllBytes();
              byte[] res =
                  ("B{" + new String(inBytes, StandardCharsets.UTF_8) + "}")
                      .getBytes(StandardCharsets.UTF_8);
              os.write(res);
              os.flush();
              return (long) res.length;
            })
        .when(b)
        .decompress(any(InputStream.class), any(java.io.OutputStream.class), anyLong(), anyLong());

    // The manager removes from the end, so to apply B then A, provide list [A, B]
    List<Compressor> decompressors = new ArrayList<>(List.of(a, b));
    DecompressorThreadManager manager = new DecompressorThreadManager(in, decompressors, 64);

    // Act
    PipedInputStream result = manager.execute();

    String original = "xyz";
    sourceOut.write(original.getBytes(StandardCharsets.UTF_8));
    sourceOut.flush();
    sourceOut.close();
    sourceOut = null;

    String out = new String(result.readAllBytes(), StandardCharsets.UTF_8);
    manager.waitFinished();

    // Assert: removeLast() builds chain so that 'b' runs first, then 'a'
    assertEquals("A[B{" + original + "}]", out);
    assertNull(manager.getError());
  }

  @Test
  @DisplayName("execute_whenManagerHasPreExistingError_throwsOnExecute")
  void execute_whenManagerHasPreExistingError_throwsOnExecute() throws Exception {
    // Arrange
    PipedInputStream in = new PipedInputStream();
    sourceOut = new PipedOutputStream(in);
    List<Compressor> decompressors = new ArrayList<>();
    DecompressorThreadManager manager = new DecompressorThreadManager(in, decompressors, 1);
    RuntimeException boom = new RuntimeException("boom");
    manager.onFailure(boom);

    // Act + Assert
    Throwable thrown = assertThrows(Throwable.class, manager::execute);
    assertSame(boom, thrown);
    assertSame(boom, manager.getError());
  }

  @Test
  @DisplayName("waitFinished_whenDecompressorThrows_propagatesError")
  void waitFinished_whenDecompressorThrows_propagatesError() throws Throwable {
    // Arrange
    PipedInputStream in = new PipedInputStream();
    sourceOut = new PipedOutputStream(in);

    Compressor failing = mock(Compressor.class);
    RuntimeException failure = new RuntimeException("decompress failed");
    doAnswer(
            _ -> {
              throw failure;
            })
        .when(failing)
        .decompress(any(InputStream.class), any(java.io.OutputStream.class), anyLong(), anyLong());

    List<Compressor> decompressors = new ArrayList<>(List.of(failing));
    DecompressorThreadManager manager = new DecompressorThreadManager(in, decompressors, 1024);

    // Act
    try (var _ = manager.execute()) {
      sourceOut.write("irrelevant".getBytes(StandardCharsets.UTF_8));
      sourceOut.flush();
      sourceOut.close();
      sourceOut = null;

      // Assert
      Throwable thrown = assertThrows(Throwable.class, manager::waitFinished);
      assertSame(failure, thrown);
      assertSame(failure, manager.getError());
    }
  }

  @ParameterizedTest
  @ValueSource(longs = {0L, 1L, -1L, 123L})
  @DisplayName("execute_whenDifferentMaxLen_passesThroughToDecompressor")
  void execute_whenDifferentMaxLen_passesThroughToDecompressor(long maxLen) throws Throwable {
    // Arrange
    PipedInputStream in = new PipedInputStream();
    sourceOut = new PipedOutputStream(in);

    Compressor mockDecompressor = mock(Compressor.class);
    // Minimal work to finish quickly so we can verify arguments deterministically.
    doReturn(0L)
        .when(mockDecompressor)
        .decompress(any(InputStream.class), any(java.io.OutputStream.class), anyLong(), anyLong());

    List<Compressor> decompressors = new ArrayList<>(List.of(mockDecompressor));
    DecompressorThreadManager manager = new DecompressorThreadManager(in, decompressors, maxLen);

    // Act
    try (var _ = manager.execute()) {
      // Close source immediately since decompressor does no reads in this stub.
      sourceOut.close();
      sourceOut = null;
      manager.waitFinished();
    }

    // Assert
    verify(mockDecompressor)
        .decompress(
            any(InputStream.class), any(java.io.OutputStream.class), eq(maxLen), eq(maxLen * 4));
    assertNull(manager.getError());
  }
}
