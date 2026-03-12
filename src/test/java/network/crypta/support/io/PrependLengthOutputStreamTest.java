package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.stubbing.Answer;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

/**
 * Tests for {@link PrependLengthOutputStream}.
 *
 * <p>AAA style, Mockito for I/O, deterministic inputs. Covers normal, abort, boundary and error
 * paths.
 */
@SuppressWarnings("java:S100") // Allow underscore-based test method names per project guidelines
class PrependLengthOutputStreamTest {

  private PrependLengthOutputStream underTest; // closed in @AfterEach when created

  @AfterEach
  void tearDown() {
    if (underTest != null) {
      // Safe double-close to assert idempotency across tests
      try {
        underTest.close();
      } catch (Throwable _) {
        // Some tests intentionally provoke errors during close; ignore here
      }
    }
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  @DisplayName("create_whenBucketFactoryNull_expectNullPointerException")
  void create_whenBucketFactoryNull_expectNullPointerException() throws IOException {
    // Arrange
    try (OutputStream out = mock(OutputStream.class)) {
      // Act + Assert
      assertThrows(
          NullPointerException.class, () -> PrependLengthOutputStream.create(out, null, 0, true));
    }
  }

  @Test
  @DisplayName("close_whenOutputStreamNull_expectNullPointerException")
  void close_whenOutputStreamNull_expectNullPointerException() throws IOException {
    // Arrange: bucket factory returning a mock temp bucket with working streams
    RandomAccessBucket tempBucket = mockTempBucketBackedBy(new ByteArrayOutputStream());
    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenReturn(tempBucket);

    // Create with null original OutputStream
    underTest = PrependLengthOutputStream.create(null, bf, 0, true);

    // Act + Assert: NPE arises when close() tries to write to DataOutputStream(null)
    assertThrows(NullPointerException.class, () -> underTest.close());
  }

  @Test
  @DisplayName("write_whenByteArray_expectSingleBulkWriteToTemp")
  void write_whenByteArray_expectSingleBulkWriteToTemp() throws IOException {
    // Arrange
    ByteArrayOutputStream tempBaos = spy(new ByteArrayOutputStream());
    RandomAccessBucket tempBucket = mockTempBucketBackedBy(tempBaos);
    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenReturn(tempBucket);
    ByteArrayOutputStream origSpy = spy(new ByteArrayOutputStream());

    underTest = PrependLengthOutputStream.create(origSpy, bf, 0, false);

    byte[] data = "abcdef".getBytes(StandardCharsets.US_ASCII);

    // Act
    underTest.write(data);

    // Assert: PrependLengthOutputStream delegates to underlying out.write(byte[],off,len)
    verify(tempBaos, times(1)).write(data, 0, data.length);
    // Ensure no per-byte writes happened
    verify(tempBaos, never()).write(anyInt());
  }

  @ParameterizedTest(name = "offset={0}")
  @MethodSource("offsetProvider")
  @DisplayName("close_whenNotAborted_writesHeaderAsSizeMinusOffset_andCopiesAllData")
  void close_whenNotAborted_writesHeaderAsSizeMinusOffset_andCopiesAllData(int offset)
      throws IOException {
    // Arrange
    byte[] payload = "hello world".getBytes(StandardCharsets.US_ASCII); // 11 bytes
    ByteArrayOutputStream tempBaos = new ByteArrayOutputStream();
    RandomAccessBucket tempBucket = mockTempBucketBackedBy(tempBaos);
    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenReturn(tempBucket);
    ByteArrayOutputStream origSpy = spy(new ByteArrayOutputStream());
    underTest = PrependLengthOutputStream.create(origSpy, bf, offset, false);

    // Act
    underTest.write(payload);
    underTest.close();

    // Assert
    byte[] written = origSpy.toByteArray();
    assertTrue(written.length >= 8, "Must have at least 8 bytes for the length header");
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(written))) {
      long header = dis.readLong();
      assertThat(header, is((long) payload.length - offset));
      byte[] copied = dis.readAllBytes();
      assertArrayEquals(payload, copied, "All payload bytes must be copied");
    }

    // temp.free() must be called
    verify(tempBucket, times(1)).free();

    // Underlying should not be closed when closeUnderlying=false
    verify(origSpy, never()).close();
  }

  static Stream<Arguments> offsetProvider() {
    return Stream.of(
        Arguments.of(0), // equal
        Arguments.of(5), // positive smaller than size
        Arguments.of(100), // larger than size (negative header)
        Arguments.of(-2) // negative offset (header larger than size)
        );
  }

  @Test
  @DisplayName("close_whenCloseUnderlyingTrue_expectUnderlyingClosed")
  void close_whenCloseUnderlyingTrue_expectUnderlyingClosed() throws IOException {
    // Arrange
    ByteArrayOutputStream tempBaos = new ByteArrayOutputStream();
    RandomAccessBucket tempBucket = mockTempBucketBackedBy(tempBaos);
    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenReturn(tempBucket);
    ByteArrayOutputStream origSpy = spy(new ByteArrayOutputStream());
    underTest = PrependLengthOutputStream.create(origSpy, bf, 0, true);

    underTest.write("123".getBytes(StandardCharsets.US_ASCII));

    // Act
    underTest.close();

    // Assert
    verify(origSpy, times(1)).close();
    verify(tempBucket, times(1)).free();
  }

  @Test
  @DisplayName("close_whenAborted_expectZeroLengthHeaderAndNoPayload")
  void close_whenAborted_expectZeroLengthHeaderAndNoPayload() throws IOException {
    // Arrange
    ByteArrayOutputStream tempBaos = new ByteArrayOutputStream();
    RandomAccessBucket tempBucket = mockTempBucketBackedBy(tempBaos);
    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenReturn(tempBucket);
    ByteArrayOutputStream origSpy = spy(new ByteArrayOutputStream());
    underTest = PrependLengthOutputStream.create(origSpy, bf, 3, false);

    underTest.write("ignored".getBytes(StandardCharsets.US_ASCII));
    assertTrue(underTest.abort());

    // Act
    underTest.close();

    // Assert
    byte[] written = origSpy.toByteArray();
    assertThat("Only header expected when aborted", written.length, is(8));
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(written))) {
      assertThat(dis.readLong(), is(0L));
      assertEquals(0, dis.available(), "No payload after aborted header");
    }
    verify(tempBucket, times(1)).free();
  }

  @Test
  @DisplayName("abort_whenClosed_expectFalse")
  void abort_whenClosed_expectFalse() throws IOException {
    // Arrange
    ByteArrayOutputStream tempBaos = new ByteArrayOutputStream();
    RandomAccessBucket tempBucket = mockTempBucketBackedBy(tempBaos);
    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenReturn(tempBucket);
    OutputStream orig = new ByteArrayOutputStream();
    underTest = PrependLengthOutputStream.create(orig, bf, 0, false);
    underTest.close();

    // Act + Assert
    assertFalse(underTest.abort());
  }

  @Test
  @DisplayName("abort_whenOpen_expectTrue")
  void abort_whenOpen_expectTrue() throws IOException {
    // Arrange
    ByteArrayOutputStream tempBaos = new ByteArrayOutputStream();
    RandomAccessBucket tempBucket = mockTempBucketBackedBy(tempBaos);
    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenReturn(tempBucket);
    OutputStream orig = new ByteArrayOutputStream();
    underTest = PrependLengthOutputStream.create(orig, bf, 0, false);

    // Act + Assert
    assertTrue(underTest.abort());
  }

  @Test
  @DisplayName("close_whenCalledTwice_expectIdempotentBehavior")
  void close_whenCalledTwice_expectIdempotentBehavior() throws IOException {
    // Arrange
    ByteArrayOutputStream tempBaos = new ByteArrayOutputStream();
    RandomAccessBucket tempBucket = mockTempBucketBackedBy(tempBaos);
    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenReturn(tempBucket);
    ByteArrayOutputStream origSpy = spy(new ByteArrayOutputStream());
    underTest = PrependLengthOutputStream.create(origSpy, bf, 1, true);

    underTest.write("xyz".getBytes(StandardCharsets.US_ASCII));

    // Act
    underTest.close();
    byte[] first = origSpy.toByteArray();
    underTest.close();
    byte[] second = origSpy.toByteArray();

    // Assert: identical bytes, no second write
    assertArrayEquals(first, second);
    verify(origSpy, times(1)).close();
  }

  @Test
  @DisplayName("write_whenNullArray_expectNullPointerException")
  @SuppressWarnings("DataFlowIssue")
  void write_whenNullArray_expectNullPointerException() throws IOException {
    // Arrange
    RandomAccessBucket tempBucket = mockTempBucketBackedBy(new ByteArrayOutputStream());
    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenReturn(tempBucket);
    OutputStream orig = new ByteArrayOutputStream();
    underTest = PrependLengthOutputStream.create(orig, bf, 0, false);

    // Act + Assert
    assertThrows(NullPointerException.class, () -> underTest.write(null));
  }

  @Test
  @DisplayName("write_whenLengthOutOfBounds_expectIndexOutOfBoundsException")
  void write_whenLengthOutOfBounds_expectIndexOutOfBoundsException() throws IOException {
    // Arrange
    RandomAccessBucket tempBucket = mockTempBucketBackedBy(new ByteArrayOutputStream());
    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenReturn(tempBucket);
    OutputStream orig = new ByteArrayOutputStream();
    underTest = PrependLengthOutputStream.create(orig, bf, 0, false);

    byte[] data = new byte[5];

    // Act + Assert
    assertThrows(IndexOutOfBoundsException.class, () -> underTest.write(data, 0, 6));
  }

  // Helpers

  /**
   * Creates a Mockito-backed {@link RandomAccessBucket} whose contents are stored in the provided
   * {@link ByteArrayOutputStream}.
   */
  private static RandomAccessBucket mockTempBucketBackedBy(ByteArrayOutputStream backingBaos)
      throws IOException {
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);

    // Output side: writes go into the provided BAOS (the stream instance must be stable)
    when(bucket.getOutputStream()).thenReturn(backingBaos);
    when(bucket.getOutputStreamUnbuffered()).thenReturn(backingBaos);

    // Size reflects current content of the BAOS
    when(bucket.size()).thenAnswer((Answer<Long>) invocation -> (long) backingBaos.size());

    // Input side used during close(): produce a fresh InputStream over the current bytes
    when(bucket.getInputStream())
        .thenAnswer(
            (Answer<java.io.InputStream>)
                invocation -> new ByteArrayInputStream(backingBaos.toByteArray()));
    when(bucket.getInputStreamUnbuffered())
        .thenAnswer(
            (Answer<java.io.InputStream>)
                invocation -> new ByteArrayInputStream(backingBaos.toByteArray()));

    // free() is verified in tests
    doNothing().when(bucket).free();

    return bucket;
  }
}
