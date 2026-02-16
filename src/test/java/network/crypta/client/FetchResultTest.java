package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FetchResultTest {

  @Mock private Bucket mockBucket;

  @Test
  void constructor_whenMetadataNull_expectIllegalArgumentException() {
    // Arrange
    ClientMetadata dm = null;
    try (ArrayBucket bucket = new ArrayBucket()) {
      // Act & Assert
      //noinspection ConstantValue
      assertThrows(IllegalArgumentException.class, () -> FetchResult.create(dm, bucket));
    }
  }

  @Test
  void constructor_whenValidParams_expectFieldsAccessible() throws IOException {
    // Arrange
    ClientMetadata dm = new ClientMetadata("text/plain");
    byte[] bytes = new byte[] {1, 2, 3, 4, 5};
    try (ArrayBucket bucket = new ArrayBucket(bytes)) {
      // Act
      FetchResult fr = FetchResult.create(dm, bucket);

      // Assert
      assertSame(dm, fr.getMetadata(), "Metadata instance should be preserved");
      assertSame(bucket, fr.asBucket(), "Bucket instance should be preserved");
      assertEquals("text/plain", fr.getMimeType());
      assertEquals(bytes.length, fr.size());
      assertArrayEquals(bytes, fr.asByteArray());
    }
  }

  @Test
  void copyConstructor_whenValid_expectMetadataCopiedAndDataReplaced() throws IOException {
    // Arrange
    ClientMetadata dm = new ClientMetadata("image/png");
    try (ArrayBucket originalData = new ArrayBucket(new byte[] {9, 9});
        ArrayBucket newData = new ArrayBucket(new byte[] {7, 8, 9})) {
      FetchResult original = FetchResult.create(dm, originalData);

      // Act
      FetchResult copy = FetchResult.create(original, newData);

      // Assert
      assertSame(dm, copy.getMetadata(), "Metadata should be taken from original");
      assertSame(newData, copy.asBucket(), "New data bucket should be used");
      assertEquals("image/png", copy.getMimeType());
      assertEquals(3, copy.size());
      assertArrayEquals(new byte[] {7, 8, 9}, copy.asByteArray());
    }
  }

  @Test
  void copyConstructor_whenOriginalNull_expectNullPointerException() {
    // Arrange
    FetchResult original = null;
    try (ArrayBucket data = new ArrayBucket()) {
      // Act & Assert
      //noinspection DataFlowIssue,ConstantValue
      assertThrows(NullPointerException.class, () -> FetchResult.create(original, data));
    }
  }

  @Test
  void getMimeType_whenDefaultMetadata_expectOctetStream() {
    // Arrange: empty metadata should yield default MIME type
    ClientMetadata dm = new ClientMetadata();
    try (ArrayBucket bucket = new ArrayBucket()) {
      // Act
      FetchResult fr = FetchResult.create(dm, bucket);

      // Assert
      assertEquals(DefaultMIMETypes.DEFAULT_MIME_TYPE, fr.getMimeType());
    }
  }

  @Test
  void asByteArray_whenEmptyBucket_expectEmptyArray() throws IOException {
    // Arrange
    ClientMetadata dm = new ClientMetadata("application/octet-stream");
    try (ArrayBucket bucket = new ArrayBucket()) {
      FetchResult fr = FetchResult.create(dm, bucket);

      // Act
      byte[] out = fr.asByteArray();

      // Assert
      assertArrayEquals(new byte[0], out);
    }
  }

  @Test
  void asByteArray_whenBucketTooLarge_expectOutOfMemoryError() {
    // Arrange
    ClientMetadata dm = new ClientMetadata("application/octet-stream");
    Bucket huge = org.mockito.Mockito.mock(Bucket.class);
    org.mockito.Mockito.when(huge.size()).thenReturn(1L + Integer.MAX_VALUE);
    FetchResult fr = FetchResult.create(dm, huge);

    // Act & Assert
    assertThrows(OutOfMemoryError.class, fr::asByteArray);
  }

  @Test
  void asByteArray_whenInputStreamThrowsIOException_expectIOException() throws IOException {
    // Arrange
    ClientMetadata dm = new ClientMetadata("application/octet-stream");
    Bucket b = org.mockito.Mockito.mock(Bucket.class);
    org.mockito.Mockito.when(b.size()).thenReturn(10L);
    org.mockito.Mockito.when(b.getInputStreamUnbuffered()).thenThrow(new IOException("boom"));
    FetchResult fr = FetchResult.create(dm, b);

    // Act & Assert
    assertThrows(IOException.class, fr::asByteArray);
  }

  @Test
  void size_whenBucketSizeThrows_expectPropagatedException() {
    // Arrange: honor constructor contract (non-null), but simulate a faulty bucket
    ClientMetadata dm = new ClientMetadata("application/octet-stream");
    Bucket bad = org.mockito.Mockito.mock(Bucket.class);
    org.mockito.Mockito.when(bad.size()).thenThrow(new NullPointerException("boom"));
    FetchResult fr = FetchResult.create(dm, bad);

    // Act & Assert
    assertThrows(NullPointerException.class, fr::size);
  }

  @Test
  void asByteArray_whenProvidedStreamMatchesSize_expectExactBytes() throws IOException {
    // Arrange: use a mock bucket that reports size and returns a matching stream
    ClientMetadata dm = new ClientMetadata("text/plain");
    byte[] data = new byte[] {42, 43, 44};
    org.mockito.Mockito.when(mockBucket.size()).thenReturn((long) data.length);
    org.mockito.Mockito.when(mockBucket.getInputStreamUnbuffered())
        .thenReturn(new ByteArrayInputStream(data));
    FetchResult fr = FetchResult.create(dm, mockBucket);

    // Act
    byte[] out = fr.asByteArray();

    // Assert
    assertArrayEquals(data, out);
  }
}
