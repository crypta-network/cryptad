package network.crypta.clients.fcp;

import java.io.IOException;
import network.crypta.client.ClientMetadata;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ArrayBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
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
            mock(NodeClientCore.class),
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
    ClientContext context = mock(ClientContext.class);
    NodeClientCore core = mock(NodeClientCore.class);

    when(core.getClientContext()).thenReturn(context);
    when(context.getBucketFactory(true)).thenReturn(new ArrayBucketFactory());

    PreparedData prepared =
        ClientPutPreparedDataFactory.prepareForPersistentUpload(
            ClientPutBase.UploadFrom.REDIRECT, metadata, bucket, target, core, true);

    assertNotNull(prepared.bucket());
    assertNotSame(bucket, prepared.bucket());
    assertEquals(target, prepared.targetUri());
    assertTrue(prepared.isMetadata());
  }

  @Test
  void prepareForPersistentUpload_whenBucketFactoryFails_throwsIOException() throws Exception {
    ClientMetadata metadata = new ClientMetadata("text/plain");
    //noinspection resource
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    FreenetURI target = new FreenetURI(VALID_CHK);
    ClientContext context = mock(ClientContext.class);
    NodeClientCore core = mock(NodeClientCore.class);
    BucketFactory bucketFactory = mock(BucketFactory.class);

    when(core.getClientContext()).thenReturn(context);
    when(context.getBucketFactory(false)).thenReturn(bucketFactory);
    when(bucketFactory.makeBucket(-1)).thenThrow(new IOException("fail"));

    assertThrows(
        IOException.class,
        () ->
            ClientPutPreparedDataFactory.prepareForPersistentUpload(
                ClientPutBase.UploadFrom.REDIRECT, metadata, bucket, target, core, false));
  }

  @Test
  void prepareForMessage_whenNotRedirect_returnsMessageBucket() throws Exception {
    ClientPutMessage message = buildMessage(ClientPutBase.UploadFrom.DIRECT, null);
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    message.bucket = bucket;

    PreparedData prepared =
        ClientPutPreparedDataFactory.prepareForMessage(
            message,
            new ClientMetadata("text/plain"),
            mock(FCPServer.class),
            false,
            ClientPutBase.UploadFrom.DIRECT,
            "id",
            false);

    assertSame(bucket, prepared.bucket());
    assertFalse(prepared.isMetadata());
    assertNull(prepared.targetUri());
  }

  @Test
  void prepareForMessage_whenRedirect_buildsMetadataBucket() throws Exception {
    ClientPutMessage message = buildMessage(ClientPutBase.UploadFrom.REDIRECT, VALID_CHK);
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    message.bucket = bucket;
    ClientContext context = mock(ClientContext.class);
    NodeClientCore core = mock(NodeClientCore.class);
    FCPServer server = mock(FCPServer.class);

    when(server.getCore()).thenReturn(core);
    when(core.getClientContext()).thenReturn(context);
    when(context.getBucketFactory(true)).thenReturn(new ArrayBucketFactory());

    PreparedData prepared =
        ClientPutPreparedDataFactory.prepareForMessage(
            message,
            new ClientMetadata("text/plain"),
            server,
            true,
            ClientPutBase.UploadFrom.REDIRECT,
            "id",
            false);

    assertNotNull(prepared.bucket());
    assertNotSame(bucket, prepared.bucket());
    assertEquals(message.redirectTarget, prepared.targetUri());
    assertTrue(prepared.isMetadata());
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
