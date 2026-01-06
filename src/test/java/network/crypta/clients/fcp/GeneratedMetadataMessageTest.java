package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class GeneratedMetadataMessageTest {

  @Mock private InputStream inputStream;
  @Mock private BucketFactory bucketFactory;
  @Mock private FCPServer server;
  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void dataLength_whenBucketHasSize_returnsBucketSize() {
    Bucket bucket = new SimpleReadOnlyArrayBucket(new byte[] {1, 2, 3, 4});
    GeneratedMetadataMessage message = new GeneratedMetadataMessage("id", false, bucket);

    long length = message.dataLength();

    assertEquals(bucket.size(), length);
  }

  @Test
  void writeData_whenCalled_writesEntireBucketToOutputStream() throws IOException {
    byte[] payload = new byte[] {0, 1, 2, 3, 4};
    Bucket bucket = new SimpleReadOnlyArrayBucket(payload);
    GeneratedMetadataMessage message = new GeneratedMetadataMessage("id", true, bucket);
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    message.writeData(output);

    assertArrayEquals(payload, output.toByteArray());
  }

  @Test
  void getFieldSet_whenInvoked_containsIdentifierGlobalAndLength() {
    byte[] payload = new byte[] {9, 8};
    Bucket bucket = new SimpleReadOnlyArrayBucket(payload);
    String identifier = "meta-id";
    GeneratedMetadataMessage message = new GeneratedMetadataMessage(identifier, true, bucket);

    SimpleFieldSet result = message.getFieldSet();

    assertNotNull(result);
    assertEquals(identifier, result.get("Identifier"));
    assertEquals("true", result.get("Global"));
    assertEquals(Long.toString(bucket.size()), result.get("DataLength"));
  }

  @Test
  void getName_whenCalled_returnsGeneratedMetadataConstant() {
    GeneratedMetadataMessage message =
        new GeneratedMetadataMessage("id", false, new SimpleReadOnlyArrayBucket(new byte[0]));

    String name = message.getName();

    assertEquals(GeneratedMetadataMessage.NAME, name);
  }

  @Test
  void readFrom_whenInvoked_throwsUnsupportedOperationException() {
    GeneratedMetadataMessage message =
        new GeneratedMetadataMessage("id", false, new SimpleReadOnlyArrayBucket(new byte[0]));

    assertThrows(
        UnsupportedOperationException.class,
        () -> message.readFrom(inputStream, bucketFactory, server));
  }

  @Test
  void run_whenInvoked_throwsUnsupportedOperationException() {
    GeneratedMetadataMessage message =
        new GeneratedMetadataMessage("id", false, new SimpleReadOnlyArrayBucket(new byte[0]));

    assertThrows(UnsupportedOperationException.class, () -> message.run(handler, node));
  }
}
