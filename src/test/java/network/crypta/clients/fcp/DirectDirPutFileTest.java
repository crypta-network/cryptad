package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.NullBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "resource"})
class DirectDirPutFileTest {

  private static final String NAME = "index.html";
  private static final String IDENTIFIER = "req-1";
  private static final boolean GLOBAL = true;

  @Mock private BucketFactory bucketFactory;
  @Mock private RandomAccessBucket bucket;

  @Test
  void create_whenDataLengthMissing_expectMessageInvalidException() {
    SimpleFieldSet subset = new SimpleFieldSet(true);

    MessageInvalidException ex =
        assertThrows(
            MessageInvalidException.class,
            () -> DirectDirPutFile.create(NAME, null, subset, IDENTIFIER, GLOBAL, bucketFactory));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    assertTrue(ex.global);
    assertTrue(ex.getMessage().contains("DataLength"));
    verifyNoInteractions(bucketFactory);
  }

  @Test
  void create_whenDataLengthNotNumeric_expectMessageInvalidException() {
    SimpleFieldSet subset = subsetWithLength("not-a-number");

    MessageInvalidException ex =
        assertThrows(
            MessageInvalidException.class,
            () -> DirectDirPutFile.create(NAME, null, subset, IDENTIFIER, GLOBAL, bucketFactory));

    assertEquals(ProtocolErrorMessage.ERROR_PARSING_NUMBER, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    assertTrue(ex.global);
    verifyNoInteractions(bucketFactory);
  }

  @Test
  void create_whenBucketFactoryFails_expectMessageInvalidException() throws IOException {
    SimpleFieldSet subset = subsetWithLength("10");
    IOException failure = new IOException("disk full");
    when(bucketFactory.makeBucket(10L)).thenThrow(failure);

    MessageInvalidException ex =
        assertThrows(
            MessageInvalidException.class,
            () -> DirectDirPutFile.create(NAME, null, subset, IDENTIFIER, GLOBAL, bucketFactory));

    assertEquals(ProtocolErrorMessage.INTERNAL_ERROR, ex.protocolCode);
    assertTrue(ex.getMessage().contains("could not allocate temp bucket"));
  }

  @Test
  void create_whenLengthZero_expectNullBucketAndZeroBytesToRead() throws MessageInvalidException {
    SimpleFieldSet subset = subsetWithLength("0");

    DirectDirPutFile file =
        DirectDirPutFile.create(NAME, null, subset, IDENTIFIER, GLOBAL, bucketFactory);

    assertEquals(0, file.bytesToRead());
    assertInstanceOf(NullBucket.class, file.getData());
    verifyNoInteractions(bucketFactory);
  }

  @Test
  void create_whenLengthPositive_usesFactoryBucketAndMimeOverride()
      throws IOException, MessageInvalidException {
    SimpleFieldSet subset = subsetWithLength("42");
    when(bucketFactory.makeBucket(42L)).thenReturn(bucket);
    String overrideMime = "text/plain";

    DirectDirPutFile file =
        DirectDirPutFile.create(NAME, overrideMime, subset, IDENTIFIER, GLOBAL, bucketFactory);

    assertSame(bucket, file.getData());
    assertEquals(42, file.bytesToRead());
    assertEquals(overrideMime, file.getMIMEType());
    verify(bucketFactory).makeBucket(42L);
  }

  @Test
  void read_whenCalled_invokesBucketToolsCopyFrom() throws Exception {
    long length = 8L;
    DirectDirPutFile file = newFileWithBucket(length);
    InputStream input = new ByteArrayInputStream(new byte[0]);

    try (MockedStatic<BucketTools> mocked = Mockito.mockStatic(BucketTools.class)) {
      file.read(input);
      mocked.verify(() -> BucketTools.copyFrom(bucket, input, length));
    }
  }

  @Test
  void write_whenCalled_invokesBucketToolsCopyTo() throws Exception {
    long length = 12L;
    DirectDirPutFile file = newFileWithBucket(length);
    OutputStream output = new ByteArrayOutputStream();

    try (MockedStatic<BucketTools> mocked = Mockito.mockStatic(BucketTools.class)) {
      mocked.when(() -> BucketTools.copyTo(bucket, output, length)).thenReturn(length);
      file.write(output);
      mocked.verify(() -> BucketTools.copyTo(bucket, output, length));
    }
  }

  @Test
  void read_whenBucketToolsThrowsIOException_propagates() throws Exception {
    long length = 5L;
    DirectDirPutFile file = newFileWithBucket(length);
    InputStream input = new ByteArrayInputStream(new byte[0]);

    try (MockedStatic<BucketTools> mocked = Mockito.mockStatic(BucketTools.class)) {
      IOException failure = new IOException("copy failure");
      mocked.when(() -> BucketTools.copyFrom(bucket, input, length)).thenThrow(failure);

      IOException thrown = assertThrows(IOException.class, () -> file.read(input));
      assertSame(failure, thrown);
    }
  }

  private DirectDirPutFile newFileWithBucket(long length) throws Exception {
    SimpleFieldSet subset = subsetWithLength(Long.toString(length));
    when(bucketFactory.makeBucket(length)).thenReturn(bucket);
    return DirectDirPutFile.create(NAME, null, subset, IDENTIFIER, GLOBAL, bucketFactory);
  }

  private static SimpleFieldSet subsetWithLength(String length) {
    SimpleFieldSet subset = new SimpleFieldSet(true);
    subset.putSingle("DataLength", length);
    return subset;
  }
}
