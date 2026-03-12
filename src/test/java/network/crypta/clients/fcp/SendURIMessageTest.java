package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100") // Test method naming convention
@ExtendWith(MockitoExtension.class)
class SendURIMessageTest {

  private static final String IDENTIFIER = "test-ident";
  private static final String NODE_IDENTIFIER = "peer-node";
  private static final String VALID_URI = "KSK@keyword";

  @Mock private DarknetPeerNode peerNode;

  @Test
  void constructor_whenUriInvalid_expectMessageInvalidException() {
    // Arrange
    SimpleFieldSet fieldSet = baseFieldSet("invalid-uri-without-at", null);

    // Act + Assert
    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new SendURIMessage(fieldSet));
    assertEquals(ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, exception.protocolCode);
    assertEquals(IDENTIFIER, exception.ident);
  }

  @Test
  void getFieldSet_whenCalled_expectUriAndBaseFieldsPreserved() throws Exception {
    // Arrange
    long dataLength = 42L;
    SendURIMessage message = new SendURIMessage(baseFieldSet(VALID_URI, dataLength));
    String uriString = new FreenetURI(VALID_URI).toString();

    // Act
    SimpleFieldSet result = message.getFieldSet();

    // Assert
    assertEquals(IDENTIFIER, result.get("Identifier"));
    assertEquals(NODE_IDENTIFIER, result.get("NodeIdentifier"));
    assertEquals(dataLength, result.getLong("DataLength", -1L));
    assertEquals(uriString, result.get("URI"));
    assertEquals(SendURIMessage.NAME, message.getName());
  }

  @Test
  void handleFeed_whenPayloadPresent_expectUtf8DescriptionForwarded() throws Exception {
    // Arrange
    SendURIMessage message = new SendURIMessage(baseFieldSet(VALID_URI, 9L));
    String description = "Résumé ☕ entry";
    message.bucket = bucketWithUtf8(description);
    when(peerNode.sendDownloadFeed(any(FreenetURI.class), anyString())).thenReturn(77);
    FreenetURI expectedUri = new FreenetURI(VALID_URI);

    // Act
    int status = message.handleFeed(peerNode);

    // Assert
    assertEquals(77, status);
    verify(peerNode).sendDownloadFeed(expectedUri, description);
  }

  @Test
  void handleFeed_whenNoPayload_expectNullDescription() throws Exception {
    // Arrange
    SendURIMessage message = new SendURIMessage(baseFieldSet(VALID_URI, null));
    when(peerNode.sendDownloadFeed(any(FreenetURI.class), isNull())).thenReturn(11);
    FreenetURI expectedUri = new FreenetURI(VALID_URI);

    // Act
    int status = message.handleFeed(peerNode);

    // Assert
    assertEquals(11, status);
    verify(peerNode).sendDownloadFeed(expectedUri, null);
  }

  @Test
  void handleFeed_whenBucketThrowsIOException_expectInvalidMessage() throws Exception {
    // Arrange
    SendURIMessage message = new SendURIMessage(baseFieldSet(VALID_URI, 1L));
    Bucket brokenBucket = mock(Bucket.class);
    when(brokenBucket.size()).thenReturn(1L);
    when(brokenBucket.getInputStreamUnbuffered()).thenThrow(new IOException("boom"));
    message.bucket = brokenBucket;

    // Act + Assert
    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.handleFeed(peerNode));
    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertNull(exception.ident);
    verify(peerNode, never()).sendDownloadFeed(any(FreenetURI.class), anyString());
  }

  private static SimpleFieldSet baseFieldSet(String uri, Long dataLength) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("NodeIdentifier", NODE_IDENTIFIER);
    fs.putSingle("URI", uri);
    if (dataLength != null) {
      fs.putSingle("DataLength", Long.toString(dataLength));
    }
    return fs;
  }

  private static ArrayBucket bucketWithUtf8(String text) throws IOException {
    ArrayBucket bucket = new ArrayBucket();
    try (OutputStream os = bucket.getOutputStream()) {
      os.write(text.getBytes(StandardCharsets.UTF_8));
    }
    return bucket;
  }
}
