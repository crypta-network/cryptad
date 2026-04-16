package network.crypta.clients.fcp;

import java.io.IOException;
import network.crypta.client.ClientMetadata;
import network.crypta.client.MetadataResolutionTarget;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ArrayBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientPutPreparedDataFactoryTest {
  private static final String VALID_CHK =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
          + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";

  @Test
  void prepareForPersistentUpload_whenNotRedirect_returnsOriginalBucket() throws Exception {
    ClientMetadata metadata = new ClientMetadata("text/plain");
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);

    PreparedData prepared =
        ClientPutPreparedDataFactory.prepareForPersistentUpload(
            ClientPutBase.UploadFrom.DIRECT,
            metadata,
            bucket,
            null,
            mock(FcpInsertRuntimeSupport.class),
            false);

    assertSame(bucket, prepared.bucket());
    assertFalse(prepared.isMetadata());
    assertNull(prepared.targetUri());
  }

  @Test
  void prepareForPersistentUpload_whenRedirect_buildsMetadataBucket() throws Exception {
    ClientMetadata metadata = new ClientMetadata("text/plain");
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    FreenetURI target = new FreenetURI(VALID_CHK);
    FcpInsertRuntimeSupport runtimeSupport = mock(FcpInsertRuntimeSupport.class);
    RandomAccessBucket redirectBucket = new ArrayBucketFactory().makeBucket(-1);
    when(runtimeSupport.createRedirectMetadataBucket(metadata, target, true))
        .thenReturn(redirectBucket);

    PreparedData prepared =
        ClientPutPreparedDataFactory.prepareForPersistentUpload(
            ClientPutBase.UploadFrom.REDIRECT, metadata, bucket, target, runtimeSupport, true);

    assertSame(redirectBucket, prepared.bucket());
    assertEquals(target, prepared.targetUri());
    assertTrue(prepared.isMetadata());
  }

  @Test
  void prepareForPersistentUpload_whenRedirectBucketCreationFails_throwsIOException()
      throws Exception {
    ClientMetadata metadata = new ClientMetadata("text/plain");
    //noinspection resource
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    FreenetURI target = new FreenetURI(VALID_CHK);
    FcpInsertRuntimeSupport runtimeSupport = mock(FcpInsertRuntimeSupport.class);
    when(runtimeSupport.createRedirectMetadataBucket(metadata, target, false))
        .thenThrow(new IOException("fail"));

    assertThrows(
        IOException.class,
        () ->
            ClientPutPreparedDataFactory.prepareForPersistentUpload(
                ClientPutBase.UploadFrom.REDIRECT,
                metadata,
                bucket,
                target,
                runtimeSupport,
                false));
  }

  @Test
  void prepareForMessage_whenNotRedirect_returnsMessageBucket() throws Exception {
    ClientPutMessage message = buildMessage(ClientPutBase.UploadFrom.DIRECT, null);
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    message.bucket = bucket;
    FcpInsertRuntimeSupport runtimeSupport = mock(FcpInsertRuntimeSupport.class);

    PreparedData prepared =
        ClientPutPreparedDataFactory.prepareForMessage(
            message,
            new ClientMetadata("text/plain"),
            runtimeSupport,
            false,
            ClientPutBase.UploadFrom.DIRECT,
            "id",
            false);

    assertSame(bucket, prepared.bucket());
    assertFalse(prepared.isMetadata());
    assertNull(prepared.targetUri());
    verifyNoInteractions(runtimeSupport);
  }

  @Test
  void prepareForMessage_whenRedirect_buildsMetadataBucket() throws Exception {
    ClientPutMessage message = buildMessage(ClientPutBase.UploadFrom.REDIRECT, VALID_CHK);
    message.bucket = mock(RandomAccessBucket.class);
    FcpInsertRuntimeSupport runtimeSupport = mock(FcpInsertRuntimeSupport.class);
    ClientMetadata metadata = new ClientMetadata("text/plain");
    RandomAccessBucket redirectBucket = new ArrayBucketFactory().makeBucket(-1);
    when(runtimeSupport.createRedirectMetadataBucket(metadata, message.redirectTarget, true))
        .thenReturn(redirectBucket);

    PreparedData prepared =
        ClientPutPreparedDataFactory.prepareForMessage(
            message,
            metadata,
            runtimeSupport,
            true,
            ClientPutBase.UploadFrom.REDIRECT,
            "id",
            false);

    assertSame(redirectBucket, prepared.bucket());
    assertEquals(message.redirectTarget, prepared.targetUri());
    assertTrue(prepared.isMetadata());
  }

  @Test
  void prepareForMessage_whenRedirectMetadataUnresolved_throwsMessageInvalidException()
      throws Exception {
    ClientPutMessage message = buildMessage(ClientPutBase.UploadFrom.REDIRECT, VALID_CHK);
    message.bucket = mock(RandomAccessBucket.class);
    ClientMetadata metadata = new ClientMetadata("text/plain");
    FcpInsertRuntimeSupport runtimeSupport = mock(FcpInsertRuntimeSupport.class);
    when(runtimeSupport.createRedirectMetadataBucket(metadata, message.redirectTarget, false))
        .thenThrow(new MetadataUnresolvedException(new MetadataResolutionTarget[0], "unresolved"));

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class,
            () ->
                ClientPutPreparedDataFactory.prepareForMessage(
                    message,
                    metadata,
                    runtimeSupport,
                    false,
                    ClientPutBase.UploadFrom.REDIRECT,
                    "id",
                    false));

    assertEquals(ProtocolErrorMessage.INTERNAL_ERROR, exception.protocolCode);
  }

  private ClientPutMessage buildMessage(ClientPutBase.UploadFrom uploadFrom, String targetUri)
      throws MessageInvalidException {
    SimpleFieldSet fields = new SimpleFieldSet(true);
    fields.putSingle("Identifier", "request-1");
    fields.putSingle("URI", "CHK@");
    if (uploadFrom == ClientPutBase.UploadFrom.DIRECT) {
      fields.putSingle("UploadFrom", "direct");
      fields.putSingle("DataLength", "4");
    } else {
      fields.putSingle("UploadFrom", "redirect");
      fields.putSingle("TargetURI", targetUri);
    }
    return new ClientPutMessage(fields);
  }
}
