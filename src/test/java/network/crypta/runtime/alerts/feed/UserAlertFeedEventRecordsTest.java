package network.crypta.runtime.alerts.feed;

import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class UserAlertFeedEventRecordsTest {

  @Test
  void basicUserAlertFeedEvent_whenTextNull_expectNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> new BasicUserAlertFeedEvent("header", "short", null, (short) 1, 123L));
  }

  @Test
  void bookmarkUserAlertFeedEvent_whenMetadataNull_expectNullPointerException() throws Exception {
    FreenetURI uri = new FreenetURI("KSK@bookmark.txt");

    assertThrows(
        NullPointerException.class,
        () ->
            new BookmarkUserAlertFeedEvent(
                "header", "short", "text", (short) 1, 123L, null, "Bookmark", uri, null, true));
  }

  @Test
  void bookmarkUserAlertFeedEvent_whenUriNull_expectNullPointerException() {
    NodeToNodeFeedMetadata metadata = new NodeToNodeFeedMetadata("source", 1L, 2L, 3L);

    assertThrows(
        NullPointerException.class,
        () ->
            new BookmarkUserAlertFeedEvent(
                "header",
                "short",
                "text",
                (short) 1,
                123L,
                metadata,
                "Bookmark",
                null,
                null,
                true));
  }

  @Test
  void uriUserAlertFeedEvent_whenUriNull_expectNullPointerException() {
    NodeToNodeFeedMetadata metadata = new NodeToNodeFeedMetadata("source", 1L, 2L, 3L);

    assertThrows(
        NullPointerException.class,
        () ->
            new UriUserAlertFeedEvent(
                "header", "short", "text", (short) 1, 123L, metadata, null, null));
  }

  @Test
  void textUserAlertFeedEvent_whenMessageTextNull_expectNullAllowed() {
    NodeToNodeFeedMetadata metadata = new NodeToNodeFeedMetadata("source", 1L, 2L, 3L);

    TextUserAlertFeedEvent event =
        new TextUserAlertFeedEvent("header", "short", "text", (short) 1, 123L, metadata, null);

    assertEquals(metadata, event.metadata());
    assertNull(event.messageText());
  }

  @Test
  void textUserAlertFeedEvent_whenMetadataNull_expectNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> new TextUserAlertFeedEvent("header", "short", "text", (short) 1, 123L, null, "x"));
  }
}
