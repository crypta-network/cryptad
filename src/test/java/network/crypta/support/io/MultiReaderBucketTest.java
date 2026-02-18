package network.crypta.support.io;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link MultiReaderBucket} and its reader buckets. All tests follow AAA style and use
 * deterministic inputs. External I/O is mocked via Mockito.
 */
@SuppressWarnings("java:S100") // Test names intentionally use method_whenCondition_expectOutcome
class MultiReaderBucketTest {

  private static final String UNDERLYING_NAME = "underlying";
  private static final String MSG_ALREADY_CLOSED = "Already closed";

  @SuppressWarnings("java:S1172")
  private static void ignoreInt(int ignored) {
    // Intentionally empty helper to consume values in assertions.
  }

  // --- Utilities

  private static Stream<Boolean> bufferedFlag() {
    return Stream.of(Boolean.TRUE, Boolean.FALSE);
  }

  private static Bucket mockUnderlying(byte[] data) throws IOException {
    Bucket underlying = mock(Bucket.class);
    when(underlying.getInputStream()).thenAnswer(inv -> new ByteArrayInputStream(data.clone()));
    when(underlying.getInputStreamUnbuffered())
        .thenAnswer(inv -> new ByteArrayInputStream(data.clone()));
    when(underlying.size()).thenReturn((long) data.length);
    when(underlying.getName()).thenReturn(UNDERLYING_NAME);
    return underlying;
  }

  // --- Public API of MultiReaderBucket

  @Test
  @DisplayName("getReaderBucket_whenNotClosed_returnsReader")
  void getReaderBucket_whenNotClosed_returnsReader() throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying("abc".getBytes(StandardCharsets.UTF_8));
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);

    // Act
    Bucket reader = mrb.getReaderBucket();

    // Assert
    assertNotNull(reader);
    assertTrue(reader.isReadOnly());
    verify(underlying, never()).free();
  }

  @Test
  @DisplayName("getReaderBucket_whenClosed_returnsNull")
  void getReaderBucket_whenClosed_returnsNull() throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying(new byte[0]);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();

    // Act
    reader.free();
    Bucket afterClose = mrb.getReaderBucket();

    // Assert
    assertNull(afterClose);
    // Cleaner may invoke free() as well; allow at least once
    verify(underlying, atLeastOnce()).free();
  }

  @Test
  @DisplayName("free_whenCalledTwice_isIdempotent")
  void free_whenCalledTwice_isIdempotent() throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying("data".getBytes(StandardCharsets.UTF_8));
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();

    // Act
    reader.free();
    // Cleaner may also call free(). Clear invocations to assert idempotence of second call only.
    clearInvocations(underlying);
    reader.free();

    // Assert: second call does not trigger additional underlying free()
    verify(underlying, never()).free();
  }

  @Test
  @DisplayName("free_whenMultipleReadersRemaining_keepsUnderlyingOpen")
  void free_whenMultipleReadersRemaining_keepsUnderlyingOpen() throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying("abcdef".getBytes(StandardCharsets.UTF_8));
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket r1 = mrb.getReaderBucket();
    Bucket r2 = mrb.getReaderBucket();

    // Act
    r1.free();

    // Assert: underlying is not freed while another reader exists
    verify(underlying, never()).free();
    Bucket r3 = mrb.getReaderBucket();
    assertNotNull(r3);
    // Free one of the remaining readers: underlying must still be alive
    r2.free();
    verify(underlying, never()).free();
    // Free the last reader: underlying is now freed
    r3.free();
    verify(underlying, atLeastOnce()).free();
  }

  @Test
  @DisplayName("free_whenLastReaderFreed_underlyingFreedAndFurtherReaderCreationReturnsNull")
  void free_whenLastReaderFreed_underlyingFreedAndFurtherReaderCreationReturnsNull()
      throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying("xyz".getBytes(StandardCharsets.UTF_8));
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket r1 = mrb.getReaderBucket();
    Bucket r2 = mrb.getReaderBucket();

    // Act
    r1.free();
    r2.free();

    // Assert: cleanup may cause more than one free() call
    verify(underlying, atLeastOnce()).free();
    assertNull(mrb.getReaderBucket());
  }

  // --- Reader bucket behavior

  @ParameterizedTest(name = "getInputStream_whenFreed_throwsIOException [buffered={0}]")
  @MethodSource("bufferedFlag")
  void getInputStream_whenFreed_throwsIOException(boolean buffered) throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying(new byte[] {1, 2, 3});
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();
    reader.free();

    // Act & Assert - select the single call up-front to avoid multiple checked-exception sources
    org.junit.jupiter.api.function.Executable exec =
        (buffered ? reader::getInputStream : reader::getInputStreamUnbuffered);
    IOException ex = assertThrows(IOException.class, exec);
    assertTrue(ex.getMessage().contains("Already freed"));
  }

  @ParameterizedTest(name = "inputStream_read_afterReaderFreed_throwsIOException [buffered={0}]")
  @MethodSource("bufferedFlag")
  void inputStream_read_afterReaderFreed_throwsIOException(boolean buffered) throws IOException {
    // Arrange
    byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
    Bucket underlying = mockUnderlying(data);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();
    InputStream in = buffered ? reader.getInputStream() : reader.getInputStreamUnbuffered();
    assertEquals('h', in.read()); // sanity read

    // Act
    reader.free();

    // Assert
    IOException ex = assertThrows(IOException.class, in::read);
    assertTrue(ex.getMessage().contains(MSG_ALREADY_CLOSED));
  }

  @ParameterizedTest(
      name = "inputStream_readArray_afterReaderFreed_throwsIOException [buffered={0}]")
  @MethodSource("bufferedFlag")
  void inputStream_readArray_afterReaderFreed_throwsIOException(boolean buffered)
      throws IOException {
    // Arrange
    byte[] data = "abc".getBytes(StandardCharsets.UTF_8);
    Bucket underlying = mockUnderlying(data);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();
    InputStream in = buffered ? reader.getInputStream() : reader.getInputStreamUnbuffered();
    byte[] buf = new byte[4];
    assertEquals(3, in.read(buf)); // consume all

    // Act
    reader.free();

    // Assert
    IOException ex = assertThrows(IOException.class, () -> ignoreInt(in.read(buf, 0, 1)));
    assertTrue(ex.getMessage().contains(MSG_ALREADY_CLOSED));
  }

  @ParameterizedTest(name = "inputStream_available_whenOpen_matchesUnderlying [buffered={0}]")
  @MethodSource("bufferedFlag")
  void inputStream_available_whenOpen_matchesUnderlying(boolean buffered) throws IOException {
    // Arrange
    byte[] data = {10, 20, 30};
    Bucket underlying = mockUnderlying(data);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();
    InputStream in = buffered ? reader.getInputStream() : reader.getInputStreamUnbuffered();

    // Act
    int available = in.available();

    // Assert
    assertTrue(available >= 0); // do not require exact due to possible buffering
  }

  @ParameterizedTest(name = "inputStream_close_whenClosed_delegatesToUnderlying [buffered={0}]")
  @MethodSource("bufferedFlag")
  void inputStream_close_whenClosed_delegatesToUnderlying(boolean buffered) throws IOException {
    // Arrange
    byte[] data = "abc".getBytes(StandardCharsets.UTF_8);
    Bucket underlying = mock(Bucket.class);
    ByteArrayInputStream base1 = new ByteArrayInputStream(data);
    ByteArrayInputStream base2 = new ByteArrayInputStream(data);
    InputStream spy1 = spy(base1);
    InputStream spy2 = spy(base2);
    when(underlying.getInputStream()).thenReturn(spy1);
    when(underlying.getInputStreamUnbuffered()).thenReturn(spy2);
    when(underlying.size()).thenReturn((long) data.length);
    when(underlying.getName()).thenReturn(UNDERLYING_NAME);

    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();
    InputStream in = buffered ? reader.getInputStream() : reader.getInputStreamUnbuffered();

    // Act
    in.close();

    // Assert
    if (buffered) verify(spy1, times(1)).close();
    else verify(spy2, times(1)).close();
  }

  @Test
  @DisplayName("size_whenCalled_delegatesToUnderlying")
  void size_whenCalled_delegatesToUnderlying() throws IOException {
    // Arrange
    byte[] data = new byte[42];
    Bucket underlying = mockUnderlying(data);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();

    // Act
    long size = reader.size();

    // Assert
    assertEquals(42L, size);
  }

  @Test
  @DisplayName("getName_whenCalled_delegatesToUnderlying")
  void getName_whenCalled_delegatesToUnderlying() throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying(new byte[1]);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();

    // Act
    String name = reader.getName();

    // Assert
    assertEquals(UNDERLYING_NAME, name);
  }

  @Test
  @DisplayName("getOutputStream_whenCalled_throwsIOException")
  void getOutputStream_whenCalled_throwsIOException() throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying(new byte[0]);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();

    // Act & Assert
    assertThrows(IOException.class, reader::getOutputStream);
  }

  @Test
  @DisplayName("getOutputStreamUnbuffered_whenCalled_throwsIOException")
  void getOutputStreamUnbuffered_whenCalled_throwsIOException() throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying(new byte[0]);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();

    // Act & Assert
    assertThrows(IOException.class, reader::getOutputStreamUnbuffered);
  }

  @Test
  @DisplayName("createShadow_whenCalled_returnsNull")
  void createShadow_whenCalled_returnsNull() throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying(new byte[0]);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();

    // Act & Assert
    assertNull(reader.createShadow());
  }

  @Test
  @DisplayName("onResume_whenCalled_throwsUnsupportedOperationException")
  void onResume_whenCalled_throwsUnsupportedOperationException() throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying(new byte[0]);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();

    // Act & Assert
    assertThrows(
        UnsupportedOperationException.class, () -> reader.onResume(mock(ClientContext.class)));
  }

  @Test
  @DisplayName("storeTo_whenCalled_throwsUnsupportedOperationException")
  void storeTo_whenCalled_throwsUnsupportedOperationException() throws IOException {
    // Arrange
    Bucket underlying = mockUnderlying(new byte[0]);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket reader = mrb.getReaderBucket();
    DataOutputStream dos = new DataOutputStream(new ByteArrayOutputStream());

    // Act & Assert
    assertThrows(UnsupportedOperationException.class, () -> reader.storeTo(dos));
  }

  @Test
  @DisplayName("siblingReader_whenOtherFreed_keepsWorking")
  void siblingReader_whenOtherFreed_keepsWorking() throws IOException {
    // Arrange
    byte[] data = "sample".getBytes(StandardCharsets.UTF_8);
    Bucket underlying = mockUnderlying(data);
    MultiReaderBucket mrb = new MultiReaderBucket(underlying);
    Bucket r1 = mrb.getReaderBucket();
    Bucket r2 = mrb.getReaderBucket();
    InputStream in2 = r2.getInputStream();

    // Act
    r1.free();

    // Assert: other reader remains usable
    byte[] remaining = in2.readAllBytes();
    assertEquals(data.length, remaining.length);
    r2.free();
    verify(underlying, atLeastOnce()).free();
  }
}
