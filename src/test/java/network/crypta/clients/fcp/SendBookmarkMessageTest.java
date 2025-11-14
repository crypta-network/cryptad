package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SendBookmarkMessageTest {

  private static final String IDENTIFIER = "test-identifier";
  private static final String NODE_IDENTIFIER = "peer-42";
  private static final String VALID_URI = "KSK@Bookmarks";
  private static final String BOOKMARK_NAME = "crypta-home";

  @Mock private DarknetPeerNode darknetPeerNode;

  @Test
  void constructor_whenNameMissing_expectMessageInvalidException() {
    SimpleFieldSet fs = baseFieldSet();
    fs.putSingle("URI", VALID_URI);
    fs.put("HasAnActivelink", true);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new SendBookmarkMessage(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
  }

  @Test
  void constructor_whenUriMalformed_expectMessageInvalidException() {
    SimpleFieldSet fs = baseFieldSet();
    fs.putSingle("Name", BOOKMARK_NAME);
    fs.putSingle("URI", "not-a-valid-uri");
    fs.put("HasAnActivelink", false);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> new SendBookmarkMessage(fs));

    assertEquals(ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, ex.protocolCode);
  }

  @Test
  void getFieldSet_whenConstructed_containsBookmarkFields() throws MessageInvalidException {
    String description = "Crypta bookmark";
    SendBookmarkMessage message = newMessage(description, true);

    SimpleFieldSet serialized = message.getFieldSet();

    assertEquals(IDENTIFIER, serialized.get("Identifier"));
    assertEquals(NODE_IDENTIFIER, serialized.get("NodeIdentifier"));
    assertEquals(BOOKMARK_NAME, serialized.get("Name"));
    assertEquals(VALID_URI, serialized.get("URI"));
    assertTrue(serialized.getBoolean("HasAnActivelink", false));
    assertEquals(
        Integer.toString(description.getBytes(StandardCharsets.UTF_8).length),
        serialized.get("DataLength"));
  }

  @Test
  void handleFeed_whenDescriptionProvided_forwardsUtf8Text() throws Exception {
    String description = "Shared bookmark ✓";
    SendBookmarkMessage message = newMessage(description, true);

    Mockito.when(
            darknetPeerNode.sendBookmarkFeed(
                Mockito.any(FreenetURI.class),
                Mockito.eq(BOOKMARK_NAME),
                Mockito.anyString(),
                Mockito.eq(true)))
        .thenReturn(77);

    int status = message.handleFeed(darknetPeerNode);

    assertEquals(77, status);
    ArgumentCaptor<FreenetURI> uriCaptor = ArgumentCaptor.forClass(FreenetURI.class);
    ArgumentCaptor<String> descriptionCaptor = ArgumentCaptor.forClass(String.class);
    Mockito.verify(darknetPeerNode)
        .sendBookmarkFeed(
            uriCaptor.capture(),
            Mockito.eq(BOOKMARK_NAME),
            descriptionCaptor.capture(),
            Mockito.eq(true));
    assertEquals(VALID_URI, uriCaptor.getValue().toString());
    assertEquals(description, descriptionCaptor.getValue());
  }

  @Test
  void handleFeed_whenNoPayload_setsNullDescription() throws Exception {
    SendBookmarkMessage message = newMessage(null, false);

    Mockito.when(
            darknetPeerNode.sendBookmarkFeed(
                Mockito.any(FreenetURI.class),
                Mockito.eq(BOOKMARK_NAME),
                Mockito.isNull(),
                Mockito.eq(false)))
        .thenReturn(12);

    int status = message.handleFeed(darknetPeerNode);

    assertEquals(12, status);
    ArgumentCaptor<String> descriptionCaptor = ArgumentCaptor.forClass(String.class);
    Mockito.verify(darknetPeerNode)
        .sendBookmarkFeed(
            Mockito.any(FreenetURI.class),
            Mockito.eq(BOOKMARK_NAME),
            descriptionCaptor.capture(),
            Mockito.eq(false));
    assertNull(descriptionCaptor.getValue());
  }

  @Test
  void handleFeed_whenBucketReadFails_wrapsIOException() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.putSingle("Name", BOOKMARK_NAME);
    fs.putSingle("URI", VALID_URI);
    fs.put("HasAnActivelink", true);
    fs.put("DataLength", 8);
    SendBookmarkMessage message = new SendBookmarkMessage(fs);
    Bucket bucket = Mockito.mock(Bucket.class);
    message.bucket = bucket;
    Mockito.when(bucket.size()).thenReturn(8L);
    Mockito.when(bucket.getInputStreamUnbuffered()).thenThrow(new IOException("boom"));

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> message.handleFeed(darknetPeerNode));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, ex.protocolCode);
    Mockito.verify(darknetPeerNode, Mockito.never())
        .sendBookmarkFeed(
            Mockito.any(FreenetURI.class),
            Mockito.anyString(),
            Mockito.any(),
            Mockito.anyBoolean());
  }

  private SimpleFieldSet baseFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("NodeIdentifier", NODE_IDENTIFIER);
    return fs;
  }

  private SendBookmarkMessage newMessage(String description, boolean hasActiveLink)
      throws MessageInvalidException {
    SimpleFieldSet fs = baseFieldSet();
    fs.putSingle("Name", BOOKMARK_NAME);
    fs.putSingle("URI", VALID_URI);
    fs.put("HasAnActivelink", hasActiveLink);
    SendBookmarkMessage message;
    if (description != null) {
      byte[] bytes = description.getBytes(StandardCharsets.UTF_8);
      fs.put("DataLength", bytes.length);
      message = new SendBookmarkMessage(fs);
      message.bucket = new ArrayBucket(bytes);
    } else {
      message = new SendBookmarkMessage(fs);
    }
    return message;
  }
}
