package network.crypta.clients.fcp.bridge;

import java.nio.charset.StandardCharsets;
import network.crypta.clients.fcp.BookmarkFeed;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.FeedMessage;
import network.crypta.clients.fcp.TextFeedMessage;
import network.crypta.clients.fcp.URIFeedMessage;
import network.crypta.keys.FreenetURI;
import network.crypta.runtime.alerts.feed.BasicUserAlertFeedEvent;
import network.crypta.runtime.alerts.feed.BookmarkUserAlertFeedEvent;
import network.crypta.runtime.alerts.feed.NodeToNodeFeedMetadata;
import network.crypta.runtime.alerts.feed.TextUserAlertFeedEvent;
import network.crypta.runtime.alerts.feed.UriUserAlertFeedEvent;
import network.crypta.runtime.alerts.feed.UserAlertFeedEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class FcpUserAlertFeedMessageFactoryTest {

  @Test
  void create_whenBasicEvent_expectFeedMessageWithTextPayloadMetadata() {
    String text = "body\nline2";
    BasicUserAlertFeedEvent event = new BasicUserAlertFeedEvent("h", "s", text, (short) 2, 123L);

    FCPMessage message = FcpUserAlertFeedMessageFactory.create(event);

    FeedMessage feed = assertInstanceOf(FeedMessage.class, message);
    assertEquals(FeedMessage.NAME, feed.getName());
    assertEquals("h", feed.getFieldSet().get("Header"));
    assertEquals("s", feed.getFieldSet().get("ShortText"));
    assertEquals("2", feed.getFieldSet().get("PriorityClass"));
    assertEquals("123", feed.getFieldSet().get("UpdatedTime"));
    assertEquals(String.valueOf(utf8Length(text)), feed.getFieldSet().get("TextLength"));
    assertEquals(String.valueOf(utf8Length(text)), feed.getFieldSet().get("DataLength"));
  }

  @Test
  void create_whenBookmarkEvent_expectBookmarkFeedWithNodeMetadataAndDescriptionPayload()
      throws Exception {
    FreenetURI uri = new FreenetURI("KSK@gpl.txt");
    String text = "full text";
    String description = "Description";
    BookmarkUserAlertFeedEvent event =
        new BookmarkUserAlertFeedEvent(
            "h",
            "s",
            text,
            (short) 1,
            234L,
            new NodeToNodeFeedMetadata("source", 11L, 22L, 33L),
            "Bookmark Title",
            uri,
            description,
            true);

    FCPMessage message = FcpUserAlertFeedMessageFactory.create(event);

    BookmarkFeed feed = assertInstanceOf(BookmarkFeed.class, message);
    assertEquals(BookmarkFeed.NAME, feed.getName());
    assertEquals("source", feed.getFieldSet().get("SourceNodeName"));
    assertEquals("11", feed.getFieldSet().get("TimeComposed"));
    assertEquals("22", feed.getFieldSet().get("TimeSent"));
    assertEquals("33", feed.getFieldSet().get("TimeReceived"));
    assertEquals("Bookmark Title", feed.getFieldSet().get("Name"));
    assertEquals(uri.toString(), feed.getFieldSet().get("URI"));
    assertEquals("true", feed.getFieldSet().get("HasAnActivelink"));
    assertEquals(String.valueOf(utf8Length(text)), feed.getFieldSet().get("TextLength"));
    assertEquals(
        String.valueOf(utf8Length(description)), feed.getFieldSet().get("DescriptionLength"));
    assertEquals(
        String.valueOf(utf8Length(text) + utf8Length(description)),
        feed.getFieldSet().get("DataLength"));
  }

  @Test
  void create_whenUriEventDescriptionMissing_expectNullBucketLengthAndUnknownTimesOmitted()
      throws Exception {
    FreenetURI uri = new FreenetURI("KSK@uri.txt");
    String text = "full text";
    UriUserAlertFeedEvent event =
        new UriUserAlertFeedEvent(
            "h",
            "s",
            text,
            (short) 3,
            345L,
            new NodeToNodeFeedMetadata("source", -1L, 55L, -1L),
            uri,
            null);

    FCPMessage message = FcpUserAlertFeedMessageFactory.create(event);

    URIFeedMessage feed = assertInstanceOf(URIFeedMessage.class, message);
    assertEquals(URIFeedMessage.NAME, feed.getName());
    assertEquals(uri.toString(), feed.getFieldSet().get("URI"));
    assertEquals("source", feed.getFieldSet().get("SourceNodeName"));
    assertNull(feed.getFieldSet().get("TimeComposed"));
    assertEquals("55", feed.getFieldSet().get("TimeSent"));
    assertNull(feed.getFieldSet().get("TimeReceived"));
    assertEquals("0", feed.getFieldSet().get("DescriptionLength"));
    assertEquals(String.valueOf(utf8Length(text)), feed.getFieldSet().get("TextLength"));
    assertEquals(String.valueOf(utf8Length(text)), feed.getFieldSet().get("DataLength"));
  }

  @Test
  void create_whenTextEventMessageMissing_expectTextFeedMessageWithNullBucketAndTimes() {
    String text = "full text";
    TextUserAlertFeedEvent event =
        new TextUserAlertFeedEvent(
            "h",
            "s",
            text,
            (short) 4,
            456L,
            new NodeToNodeFeedMetadata("source", 77L, -1L, 99L),
            null);

    FCPMessage message = FcpUserAlertFeedMessageFactory.create(event);

    TextFeedMessage feed = assertInstanceOf(TextFeedMessage.class, message);
    assertEquals(TextFeedMessage.NAME, feed.getName());
    assertEquals("source", feed.getFieldSet().get("SourceNodeName"));
    assertEquals("77", feed.getFieldSet().get("TimeComposed"));
    assertNull(feed.getFieldSet().get("TimeSent"));
    assertEquals("99", feed.getFieldSet().get("TimeReceived"));
    assertEquals("0", feed.getFieldSet().get("MessageTextLength"));
    assertEquals(String.valueOf(utf8Length(text)), feed.getFieldSet().get("TextLength"));
    assertEquals(String.valueOf(utf8Length(text)), feed.getFieldSet().get("DataLength"));
  }

  @Test
  void create_whenEventNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> FcpUserAlertFeedMessageFactory.create(null));
  }

  @Test
  void create_whenEventTypeUnsupported_expectIllegalArgumentException() {
    UnsupportedUserAlertFeedEvent event = new UnsupportedUserAlertFeedEvent();

    assertThrows(
        IllegalArgumentException.class, () -> FcpUserAlertFeedMessageFactory.create(event));
  }

  private static int utf8Length(String value) {
    return value.getBytes(StandardCharsets.UTF_8).length;
  }

  private static final class UnsupportedUserAlertFeedEvent implements UserAlertFeedEvent {}
}
