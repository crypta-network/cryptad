package network.crypta.runtime.alerts;

import java.lang.ref.WeakReference;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.runtime.alerts.feed.BookmarkUserAlertFeedEvent;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // descriptive test method names
class BookmarkFeedUserAlertTest {

  private static NodeToNodeAlertContext alertContext(
      DarknetPeerNode peer, int fileNumber, long composed, long sent, long received) {
    return new NodeToNodeAlertContext(peer, fileNumber, composed, sent, received);
  }

  @Test
  void title_text_html_whenDescriptionPresent_expectLocalizedAndStructured()
      throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Alice");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));

    String name = "My Site";
    String description = "Line1\nLine2";
    boolean hasAnActivelink = true;
    FreenetURI uri = new FreenetURI("KSK@mysite");
    BookmarkFeedUserAlert alert =
        new BookmarkFeedUserAlert(
            alertContext(peer, 42, 1111L, 2222L, 3333L), name, description, hasAnActivelink, uri);

    // Act
    String title = alert.getTitle();
    String shortText = alert.getShortText();
    String text = alert.getText();
    HTMLNode html = alert.getHTMLText();

    // Assert: title and short text use l10n with the peer name
    assertEquals("Alice recommends you a freesite", title);
    assertEquals(title, shortText);

    // Assert: text includes Name, URI and description labels and content
    assertEquals(
        "Name: " + name + "\n" + "URI: " + uri + "\n" + "Description: " + description, text);

    // Assert: HTML structure
    assertEquals("div", html.getName());
    var children = html.getChildren();

    // First: add-as-bookmark button anchor with img
    HTMLNode a0 = children.getFirst();
    assertEquals("a", a0.getName());
    assertEquals(
        "/?newbookmark=" + uri + "&desc=" + name + "&hasAnActivelink=" + hasAnActivelink,
        a0.getAttribute("href"));
    HTMLNode img = a0.getChildren().getFirst();
    assertEquals("img", img.getName());
    assertEquals(
        Map.of(
            "src", "/static/icon/bookmark-new.png",
            "alt", "Add as a bookmark",
            "title", "Add as a bookmark"),
        img.getAttributes());

    // Second: anchor to the freesite with the name as text
    HTMLNode a1 = children.get(1);
    assertEquals("a", a1.getName());
    assertEquals("/freenet:" + uri, a1.getAttribute("href"));
    assertEquals("#", a1.getChildren().getFirst().getName());
    assertEquals(name, a1.getChildren().getFirst().getContent());

    // Followed by <br/><br/>Description:<br/>Line1<br/>Line2
    assertEquals("br", children.get(2).getName());
    assertEquals("br", children.get(3).getName());
    assertEquals("#", children.get(4).getName());
    assertEquals("Description:", children.get(4).getContent());
    assertEquals("br", children.get(5).getName());
    assertEquals("#", children.get(6).getName());
    assertEquals("Line1", children.get(6).getContent());
    assertEquals("br", children.get(7).getName());
    assertEquals("#", children.get(8).getName());
    assertEquals("Line2", children.get(8).getContent());

    // Also verify dismiss button label is localized
    assertEquals("Delete", alert.dismissButtonText());
    // Priority is minor
    assertEquals(UserAlert.MINOR, alert.getPriorityClass());
  }

  @Test
  void text_whenDescriptionNull_expectOnlyNameAndUriLines() throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Bob");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));

    String name = "Site";
    FreenetURI uri = new FreenetURI("KSK@file.txt");
    BookmarkFeedUserAlert alert =
        new BookmarkFeedUserAlert(alertContext(peer, 7, 1L, -1L, -1L), name, null, false, uri);

    // Act
    String text = alert.getText();
    HTMLNode html = alert.getHTMLText();

    // Assert
    assertEquals("Name: " + name + "\n" + "URI: " + uri + "\n", text);
    assertEquals("div", html.getName());
    var children = html.getChildren();
    // Only the two anchors should be present when the description is null
    assertEquals(2, children.size());
    assertEquals("a", children.get(0).getName());
    assertEquals("a", children.get(1).getName());
  }

  @Test
  void html_whenDescriptionEmpty_expectNoDescriptionBlock() throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Carol");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));
    FreenetURI uri = new FreenetURI("KSK@x.txt");
    BookmarkFeedUserAlert alert =
        new BookmarkFeedUserAlert(alertContext(peer, 3, -1L, -1L, -1L), "X", "", false, uri);

    // Act
    HTMLNode html = alert.getHTMLText();

    // Assert: only the two anchors present
    assertEquals(2, html.getChildren().size());
    assertEquals("a", html.getChildren().get(0).getName());
    assertEquals("a", html.getChildren().get(1).getName());
  }

  @Test
  void onDismiss_whenPeerPresent_invokesDeletion() throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Dave");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));
    FreenetURI uri = new FreenetURI("KSK@offer.txt");
    int fileNumber = 99;
    BookmarkFeedUserAlert alert =
        new BookmarkFeedUserAlert(
            alertContext(peer, fileNumber, 10L, 20L, 30L), "Title", "desc", true, uri);

    // Act
    alert.onDismiss();

    // Assert
    verify(peer).deleteExtraPeerDataFile(fileNumber);
  }

  @Test
  void onDismiss_whenPeerReferenceGone_doesNothing() throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Eve");
    // The weak reference resolves to null
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(null));
    FreenetURI uri = new FreenetURI("KSK@abc.txt");
    BookmarkFeedUserAlert alert =
        new BookmarkFeedUserAlert(alertContext(peer, 5, -1L, -1L, -1L), "S", null, false, uri);

    // Act
    alert.onDismiss();

    // Assert: no deletion attempted
    verify(peer, never()).deleteExtraPeerDataFile(anyInt());
  }

  @Test
  void isValid_whenPeerNameChanges_updatesTitle() throws MalformedURLException {
    // Arrange: first call returns initial name (constructor), second call returns updated name
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Alice", "Mallory");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));
    FreenetURI uri = new FreenetURI("KSK@z.txt");
    BookmarkFeedUserAlert alert =
        new BookmarkFeedUserAlert(alertContext(peer, 1, -1L, -1L, -1L), "S", null, false, uri);

    // Sanity: initial title uses first name
    assertEquals("Alice recommends you a freesite", alert.getTitle());

    // Act: isValid() refreshes source node name from the weak reference
    boolean stillValid = alert.isValid();

    // Assert
    assertTrue(stillValid);
    assertEquals("Mallory recommends you a freesite", alert.getTitle());
  }

  @Test
  void getFeedEvent_whenPopulated_expectBookmarkFeedWithFields() throws MalformedURLException {
    // Arrange
    DarknetPeerNode peer = mock(DarknetPeerNode.class);
    when(peer.getName()).thenReturn("Frank");
    when(peer.getWeakRef()).thenReturn(new WeakReference<>(peer));
    FreenetURI uri = new FreenetURI("KSK@data.bin");
    String description = "hello"; // 5 bytes in UTF-8
    String name = "Title";
    boolean hasAnActivelink = false;
    BookmarkFeedUserAlert alert =
        new BookmarkFeedUserAlert(
            alertContext(peer, 11, 123L, -1L, 789L), name, description, hasAnActivelink, uri);

    long updatedTime = alert.getUpdatedTime();
    String expectedTitle = alert.getTitle();
    int descriptionLen = description.getBytes(StandardCharsets.UTF_8).length;

    // Act
    BookmarkUserAlertFeedEvent event = (BookmarkUserAlertFeedEvent) alert.getFeedEvent();

    // Assert fields present and correct
    assertEquals(expectedTitle, event.header());
    assertEquals(alert.getShortText(), event.shortText());
    assertEquals(alert.getText(), event.text());
    assertEquals(alert.getPriorityClass(), event.priorityClass());
    assertEquals(updatedTime, event.updatedTime());
    assertEquals("Frank", event.metadata().sourceNodeName());
    assertEquals(123L, event.metadata().composed());
    assertEquals(-1L, event.metadata().sent());
    assertEquals(789L, event.metadata().received());
    assertEquals(name, event.bookmarkTitle());
    assertEquals(uri, event.uri());
    assertEquals(description, event.description());
    assertEquals(hasAnActivelink, event.hasActiveLink());

    // The feed event preserves the alert's textual content and bookmark payload.
    int textLen = alert.getText().getBytes(StandardCharsets.UTF_8).length;
    assertEquals(textLen, event.text().getBytes(StandardCharsets.UTF_8).length);
    assertEquals(descriptionLen, event.description().getBytes(StandardCharsets.UTF_8).length);
  }
}
