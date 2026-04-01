package network.crypta.clients.fcp.bridge;

import network.crypta.clients.fcp.BookmarkFeed;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.keys.FreenetURI;
import network.crypta.runtime.alerts.feed.BookmarkUserAlertFeedEvent;
import network.crypta.runtime.alerts.feed.NodeToNodeFeedMetadata;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings("java:S100")
class FcpUserAlertFeedSubscriberTest {

  @Test
  void constructor_whenHandlerNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> new FcpUserAlertFeedSubscriber(null));
  }

  @Test
  void equals_whenWrappedHandlerMatches_expectEqualSubscriber() {
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);

    FcpUserAlertFeedSubscriber first = new FcpUserAlertFeedSubscriber(handler);
    FcpUserAlertFeedSubscriber second = new FcpUserAlertFeedSubscriber(handler);

    assertEquals(first, second);
    assertEquals(first.hashCode(), second.hashCode());
  }

  @Test
  void equals_whenWrappedHandlerDiffers_expectNotEqualSubscriber() {
    FcpUserAlertFeedSubscriber first =
        new FcpUserAlertFeedSubscriber(mock(FCPConnectionHandler.class));
    FcpUserAlertFeedSubscriber second =
        new FcpUserAlertFeedSubscriber(mock(FCPConnectionHandler.class));

    assertNotEquals(first, second);
  }

  @Test
  void send_whenBookmarkEvent_expectEncodedBookmarkFeedSentToHandler() throws Exception {
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    FcpUserAlertFeedSubscriber subscriber = new FcpUserAlertFeedSubscriber(handler);
    FreenetURI uri = new FreenetURI("KSK@bookmark.txt");
    BookmarkUserAlertFeedEvent event =
        new BookmarkUserAlertFeedEvent(
            "header",
            "short",
            "text",
            (short) 1,
            123L,
            new NodeToNodeFeedMetadata("source", 11L, 22L, 33L),
            "Bookmark",
            uri,
            "Description",
            true);
    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);

    subscriber.send(event);

    verify(handler).send(messageCaptor.capture());
    BookmarkFeed feed = assertInstanceOf(BookmarkFeed.class, messageCaptor.getValue());
    assertEquals("Bookmark", feed.getFieldSet().get("Name"));
    assertEquals(uri.toString(), feed.getFieldSet().get("URI"));
    assertEquals("source", feed.getFieldSet().get("SourceNodeName"));
  }

  @Test
  void send_whenEventNull_expectNullPointerExceptionWithoutHandlerInteraction() {
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    FcpUserAlertFeedSubscriber subscriber = new FcpUserAlertFeedSubscriber(handler);

    assertThrows(NullPointerException.class, () -> subscriber.send(null));

    verifyNoInteractions(handler);
  }
}
