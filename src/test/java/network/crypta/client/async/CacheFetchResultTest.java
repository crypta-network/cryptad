package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import network.crypta.client.ClientMetadata;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CacheFetchResultTest {

  @Mock private Bucket mockBucket;

  @ParameterizedTest
  @CsvSource({"true", "false"})
  void constructor_whenValid_expectFieldsAndFlagPropagated(boolean alreadyFiltered)
      throws IOException {
    // Arrange
    ClientMetadata dm = new ClientMetadata("text/plain");
    byte[] data = new byte[] {1, 2, 3};
    try (ArrayBucket bucket = new ArrayBucket(data)) {
      // Act
      CacheFetchResult res = new CacheFetchResult(dm, bucket, alreadyFiltered);

      // Assert
      assertSame(dm, res.getMetadata(), "Metadata instance should be preserved");
      assertSame(bucket, res.asBucket(), "Bucket instance should be preserved");
      assertEquals("text/plain", res.getMimeType());
      assertEquals(data.length, res.size());
      assertArrayEquals(data, res.asByteArray());
      org.junit.jupiter.api.Assertions.assertEquals(
          alreadyFiltered, res.alreadyFiltered, "Flag should reflect constructor argument");
    }
  }

  @Test
  void constructor_whenMetadataNull_expectIllegalArgumentException() {
    // Arrange
    ClientMetadata dm = null;
    try (ArrayBucket bucket = new ArrayBucket()) {
      // Act & Assert
      //noinspection ConstantValue
      assertThrows(IllegalArgumentException.class, () -> new CacheFetchResult(dm, bucket, false));
    }
  }

  @Test
  void constructor_whenBucketNull_expectIllegalArgumentException() {
    // Arrange
    ClientMetadata dm = new ClientMetadata("application/octet-stream");
    Bucket bucket = null;

    // Act & Assert
    //noinspection ConstantValue
    assertThrows(IllegalArgumentException.class, () -> new CacheFetchResult(dm, bucket, true));
  }

  @Test
  void getMimeType_whenDefaultMetadata_expectOctetStream() {
    // Arrange: empty metadata should yield default MIME type via inherited method
    ClientMetadata dm = new ClientMetadata();
    try (ArrayBucket bucket = new ArrayBucket()) {
      CacheFetchResult res = new CacheFetchResult(dm, bucket, false);

      // Act & Assert
      assertEquals(DefaultMIMETypes.DEFAULT_MIME_TYPE, res.getMimeType());
    }
  }

  @Test
  void asByteArray_whenDelegatingToBucket_expectExactBytes() throws IOException {
    // Arrange: use a mock Bucket to ensure inherited behavior reads via the bucket
    ClientMetadata dm = new ClientMetadata("text/plain");
    byte[] bytes = new byte[] {42, 43, 44, 45};
    Mockito.when(mockBucket.size()).thenReturn((long) bytes.length);
    Mockito.when(mockBucket.getInputStreamUnbuffered()).thenReturn(new ByteArrayInputStream(bytes));

    CacheFetchResult res = new CacheFetchResult(dm, mockBucket, true);

    // Act
    byte[] out = res.asByteArray();

    // Assert
    assertArrayEquals(bytes, out);
  }
}
